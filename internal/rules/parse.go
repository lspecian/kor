// Package rules evaluates Firestore security rules (rules_version 2) for
// requests from end users. It parses the rules file as written and supports
// the language subset Firestore projects use in practice: nested match blocks
// with single and recursive wildcards, functions (with let bindings), allow
// statements, path literals with $(...) interpolation, get()/exists(), map,
// list, string and map-diff methods, `in`, `is`, the ternary operator and
// Firestore's error semantics for && and ||.
//
// Modified in this fork: this package is new.
package rules

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Ruleset is a parsed rules file.
type Ruleset struct {
	root *block // the service block; its matches start at the database root
}

type block struct {
	pattern   []segment // empty for the service block
	functions map[string]*function
	allows    []*allow
	matches   []*block
}

type segment struct {
	literal   string
	variable  string // non-empty for {var} and {var=**}
	recursive bool
}

type function struct {
	params []string
	lets   []letBinding
	body   expr
}

type letBinding struct {
	name string
	val  expr
}

type allow struct {
	methods []string
	cond    expr // nil means true
}

// Parse parses a rules file.
func Parse(src string) (*Ruleset, error) {
	p := &parser{src: src}
	rs, err := p.parseFile()
	if err != nil {
		line := 1 + strings.Count(src[:min(p.pos, len(src))], "\n")
		return nil, fmt.Errorf("rules: line %d: %w", line, err)
	}
	return rs, nil
}

type parser struct {
	src string
	pos int
}

func (p *parser) skipSpace() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.pos++
		case strings.HasPrefix(p.src[p.pos:], "//"):
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case strings.HasPrefix(p.src[p.pos:], "/*"):
			end := strings.Index(p.src[p.pos+2:], "*/")
			if end < 0 {
				p.pos = len(p.src)
				return
			}
			p.pos += end + 4
		default:
			return
		}
	}
}

func (p *parser) peek(s string) bool {
	p.skipSpace()
	return strings.HasPrefix(p.src[p.pos:], s)
}

// peekWord matches a keyword followed by a non-identifier character.
func (p *parser) peekWord(w string) bool {
	p.skipSpace()
	if !strings.HasPrefix(p.src[p.pos:], w) {
		return false
	}
	end := p.pos + len(w)
	return end >= len(p.src) || !isIdent(rune(p.src[end]))
}

func (p *parser) accept(s string) bool {
	if p.peek(s) {
		p.pos += len(s)
		return true
	}
	return false
}

func (p *parser) acceptWord(w string) bool {
	if p.peekWord(w) {
		p.pos += len(w)
		return true
	}
	return false
}

func (p *parser) expect(s string) error {
	if !p.accept(s) {
		return fmt.Errorf("expected %q near %q", s, p.near())
	}
	return nil
}

func (p *parser) near() string {
	end := min(p.pos+24, len(p.src))
	return p.src[p.pos:end]
}

func isIdent(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }

func (p *parser) ident() (string, error) {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.src) && isIdent(rune(p.src[p.pos])) {
		p.pos++
	}
	if start == p.pos {
		return "", fmt.Errorf("expected identifier near %q", p.near())
	}
	return p.src[start:p.pos], nil
}

func (p *parser) parseFile() (*Ruleset, error) {
	if p.acceptWord("rules_version") {
		if err := p.expect("="); err != nil {
			return nil, err
		}
		if _, err := p.stringLit(); err != nil {
			return nil, err
		}
		p.accept(";")
	}
	if !p.acceptWord("service") {
		return nil, fmt.Errorf("expected service declaration")
	}
	name := ""
	for {
		part, err := p.ident()
		if err != nil {
			return nil, err
		}
		name += part
		if !p.accept(".") {
			break
		}
		name += "."
	}
	if name != "cloud.firestore" {
		return nil, fmt.Errorf("service %q is not cloud.firestore", name)
	}
	root, err := p.blockBody(nil)
	if err != nil {
		return nil, err
	}
	return &Ruleset{root: root}, nil
}

// blockBody parses `{ statements }`.
func (p *parser) blockBody(pattern []segment) (*block, error) {
	if err := p.expect("{"); err != nil {
		return nil, err
	}
	b := &block{pattern: pattern, functions: map[string]*function{}}
	for {
		switch {
		case p.accept("}"):
			return b, nil
		case p.acceptWord("match"):
			pat, err := p.matchPattern()
			if err != nil {
				return nil, err
			}
			child, err := p.blockBody(pat)
			if err != nil {
				return nil, err
			}
			b.matches = append(b.matches, child)
		case p.acceptWord("allow"):
			a, err := p.allowStmt()
			if err != nil {
				return nil, err
			}
			b.allows = append(b.allows, a)
		case p.acceptWord("function"):
			name, fn, err := p.functionDecl()
			if err != nil {
				return nil, err
			}
			b.functions[name] = fn
		case p.pos >= len(p.src):
			return nil, fmt.Errorf("unexpected end of file")
		default:
			return nil, fmt.Errorf("unexpected %q", p.near())
		}
	}
}

func (p *parser) matchPattern() ([]segment, error) {
	p.skipSpace()
	var segs []segment
	for p.pos < len(p.src) && p.src[p.pos] == '/' {
		p.pos++
		if p.pos < len(p.src) && p.src[p.pos] == '{' {
			end := strings.IndexByte(p.src[p.pos:], '}')
			if end < 0 {
				return nil, fmt.Errorf("unclosed wildcard")
			}
			inner := p.src[p.pos+1 : p.pos+end]
			p.pos += end + 1
			seg := segment{variable: inner}
			if strings.HasSuffix(inner, "=**") {
				seg = segment{variable: strings.TrimSuffix(inner, "=**"), recursive: true}
			}
			segs = append(segs, seg)
			continue
		}
		start := p.pos
		for p.pos < len(p.src) && !strings.ContainsRune("/ {\t\n\r", rune(p.src[p.pos])) {
			p.pos++
		}
		segs = append(segs, segment{literal: p.src[start:p.pos]})
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("expected match path near %q", p.near())
	}
	return segs, nil
}

func (p *parser) allowStmt() (*allow, error) {
	a := &allow{}
	for {
		m, err := p.ident()
		if err != nil {
			return nil, err
		}
		switch m {
		case "read", "write", "get", "list", "create", "update", "delete":
		default:
			return nil, fmt.Errorf("unknown method %q", m)
		}
		a.methods = append(a.methods, m)
		if !p.accept(",") {
			break
		}
	}
	if p.accept(":") {
		if !p.acceptWord("if") {
			return nil, fmt.Errorf("expected if")
		}
		cond, err := p.expr()
		if err != nil {
			return nil, err
		}
		a.cond = cond
	}
	p.accept(";")
	return a, nil
}

func (p *parser) functionDecl() (string, *function, error) {
	name, err := p.ident()
	if err != nil {
		return "", nil, err
	}
	if err := p.expect("("); err != nil {
		return "", nil, err
	}
	fn := &function{}
	if !p.accept(")") {
		for {
			param, err := p.ident()
			if err != nil {
				return "", nil, err
			}
			fn.params = append(fn.params, param)
			if p.accept(")") {
				break
			}
			if err := p.expect(","); err != nil {
				return "", nil, err
			}
		}
	}
	if err := p.expect("{"); err != nil {
		return "", nil, err
	}
	for p.acceptWord("let") {
		n, err := p.ident()
		if err != nil {
			return "", nil, err
		}
		if err := p.expect("="); err != nil {
			return "", nil, err
		}
		v, err := p.expr()
		if err != nil {
			return "", nil, err
		}
		p.accept(";")
		fn.lets = append(fn.lets, letBinding{name: n, val: v})
	}
	if !p.acceptWord("return") {
		return "", nil, fmt.Errorf("expected return in function %s", name)
	}
	body, err := p.expr()
	if err != nil {
		return "", nil, err
	}
	fn.body = body
	p.accept(";")
	if err := p.expect("}"); err != nil {
		return "", nil, err
	}
	return name, fn, nil
}

// Expressions.

type expr interface{}

type (
	litExpr   struct{ v Value }
	identExpr struct{ name string }
	unaryExpr struct {
		op string
		x  expr
	}
	binaryExpr struct {
		op   string
		l, r expr
	}
	isExpr struct {
		x    expr
		kind string
	}
	condExpr   struct{ c, t, f expr }
	memberExpr struct {
		x    expr
		name string
	}
	indexExpr struct{ x, i expr }
	callExpr  struct {
		fn   expr // identExpr or memberExpr (method call)
		args []expr
	}
	listExpr struct{ items []expr }
	mapExpr  struct {
		keys []string
		vals []expr
	}
	pathExpr struct{ parts []pathPart }
)

type pathPart struct {
	literal string
	interp  expr // non-nil for $(expr)
}

func (p *parser) expr() (expr, error) { return p.ternary() }

func (p *parser) ternary() (expr, error) {
	c, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.accept("?") {
		t, err := p.ternary()
		if err != nil {
			return nil, err
		}
		if err := p.expect(":"); err != nil {
			return nil, err
		}
		f, err := p.ternary()
		if err != nil {
			return nil, err
		}
		return &condExpr{c, t, f}, nil
	}
	return c, nil
}

func (p *parser) or() (expr, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.accept("||") {
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = &binaryExpr{"||", l, r}
	}
	return l, nil
}

func (p *parser) and() (expr, error) {
	l, err := p.relational()
	if err != nil {
		return nil, err
	}
	for p.accept("&&") {
		r, err := p.relational()
		if err != nil {
			return nil, err
		}
		l = &binaryExpr{"&&", l, r}
	}
	return l, nil
}

func (p *parser) relational() (expr, error) {
	l, err := p.additive()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.accept("=="):
			r, err := p.additive()
			if err != nil {
				return nil, err
			}
			l = &binaryExpr{"==", l, r}
		case p.accept("!="):
			r, err := p.additive()
			if err != nil {
				return nil, err
			}
			l = &binaryExpr{"!=", l, r}
		case p.accept("<="):
			r, err := p.additive()
			if err != nil {
				return nil, err
			}
			l = &binaryExpr{"<=", l, r}
		case p.accept(">="):
			r, err := p.additive()
			if err != nil {
				return nil, err
			}
			l = &binaryExpr{">=", l, r}
		case p.peek("<") && !p.peek("<="):
			p.accept("<")
			r, err := p.additive()
			if err != nil {
				return nil, err
			}
			l = &binaryExpr{"<", l, r}
		case p.peek(">") && !p.peek(">="):
			p.accept(">")
			r, err := p.additive()
			if err != nil {
				return nil, err
			}
			l = &binaryExpr{">", l, r}
		case p.acceptWord("in"):
			r, err := p.additive()
			if err != nil {
				return nil, err
			}
			l = &binaryExpr{"in", l, r}
		case p.acceptWord("is"):
			kind, err := p.ident()
			if err != nil {
				return nil, err
			}
			l = &isExpr{l, kind}
		default:
			return l, nil
		}
	}
}

func (p *parser) additive() (expr, error) {
	l, err := p.multiplicative()
	if err != nil {
		return nil, err
	}
	for {
		var op string
		switch {
		case p.peek("+"):
			op = "+"
		case p.peek("-"):
			op = "-"
		default:
			return l, nil
		}
		p.pos++
		r, err := p.multiplicative()
		if err != nil {
			return nil, err
		}
		l = &binaryExpr{op, l, r}
	}
}

func (p *parser) multiplicative() (expr, error) {
	l, err := p.unary()
	if err != nil {
		return nil, err
	}
	for {
		var op string
		switch {
		case p.peek("*"):
			op = "*"
		case p.peek("/") && !p.peek("//"):
			op = "/"
		case p.peek("%"):
			op = "%"
		default:
			return l, nil
		}
		p.pos++
		r, err := p.unary()
		if err != nil {
			return nil, err
		}
		l = &binaryExpr{op, l, r}
	}
}

func (p *parser) unary() (expr, error) {
	if p.accept("!") {
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &unaryExpr{"!", x}, nil
	}
	if p.peek("-") {
		p.pos++
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &unaryExpr{"-", x}, nil
	}
	return p.postfix()
}

func (p *parser) postfix() (expr, error) {
	x, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.accept("."):
			name, err := p.ident()
			if err != nil {
				return nil, err
			}
			x = &memberExpr{x, name}
		case p.accept("["):
			i, err := p.expr()
			if err != nil {
				return nil, err
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			x = &indexExpr{x, i}
		case p.accept("("):
			args, err := p.args(")")
			if err != nil {
				return nil, err
			}
			x = &callExpr{x, args}
		default:
			return x, nil
		}
	}
}

func (p *parser) args(closing string) ([]expr, error) {
	var out []expr
	if p.accept(closing) {
		return out, nil
	}
	for {
		a, err := p.expr()
		if err != nil {
			return nil, err
		}
		out = append(out, a)
		if p.accept(closing) {
			return out, nil
		}
		if err := p.expect(","); err != nil {
			return nil, err
		}
	}
}

func (p *parser) primary() (expr, error) {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return nil, fmt.Errorf("unexpected end of expression")
	}
	c := p.src[p.pos]
	switch {
	case c == '(':
		p.pos++
		x, err := p.expr()
		if err != nil {
			return nil, err
		}
		return x, p.expect(")")
	case c == '[':
		p.pos++
		items, err := p.args("]")
		if err != nil {
			return nil, err
		}
		return &listExpr{items}, nil
	case c == '{':
		p.pos++
		m := &mapExpr{}
		if p.accept("}") {
			return m, nil
		}
		for {
			var key string
			var err error
			if p.peek("'") || p.peek(`"`) {
				key, err = p.stringLit()
			} else {
				key, err = p.ident()
			}
			if err != nil {
				return nil, err
			}
			if err := p.expect(":"); err != nil {
				return nil, err
			}
			v, err := p.expr()
			if err != nil {
				return nil, err
			}
			m.keys = append(m.keys, key)
			m.vals = append(m.vals, v)
			if p.accept("}") {
				return m, nil
			}
			if err := p.expect(","); err != nil {
				return nil, err
			}
		}
	case c == '\'' || c == '"':
		s, err := p.stringLit()
		if err != nil {
			return nil, err
		}
		return &litExpr{s}, nil
	case c == '/':
		return p.pathLit()
	case c >= '0' && c <= '9':
		start := p.pos
		for p.pos < len(p.src) && (p.src[p.pos] >= '0' && p.src[p.pos] <= '9' || p.src[p.pos] == '.') {
			p.pos++
		}
		lit := p.src[start:p.pos]
		if strings.Contains(lit, ".") {
			f, err := strconv.ParseFloat(lit, 64)
			return &litExpr{f}, err
		}
		n, err := strconv.ParseInt(lit, 10, 64)
		return &litExpr{n}, err
	}
	name, err := p.ident()
	if err != nil {
		return nil, err
	}
	switch name {
	case "true":
		return &litExpr{true}, nil
	case "false":
		return &litExpr{false}, nil
	case "null":
		return &litExpr{nil}, nil
	}
	return &identExpr{name}, nil
}

func (p *parser) stringLit() (string, error) {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return "", fmt.Errorf("expected string")
	}
	q := p.src[p.pos]
	if q != '\'' && q != '"' {
		return "", fmt.Errorf("expected string near %q", p.near())
	}
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) && p.src[p.pos] != q {
		if p.src[p.pos] == '\\' && p.pos+1 < len(p.src) {
			p.pos++
			switch p.src[p.pos] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(p.src[p.pos])
			}
			p.pos++
			continue
		}
		b.WriteByte(p.src[p.pos])
		p.pos++
	}
	if p.pos >= len(p.src) {
		return "", fmt.Errorf("unterminated string")
	}
	p.pos++
	return b.String(), nil
}

// pathLit parses /a/$(expr)/b.
func (p *parser) pathLit() (expr, error) {
	pe := &pathExpr{}
	for p.pos < len(p.src) && p.src[p.pos] == '/' {
		p.pos++
		if strings.HasPrefix(p.src[p.pos:], "$(") {
			p.pos += 2
			x, err := p.expr()
			if err != nil {
				return nil, err
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
			pe.parts = append(pe.parts, pathPart{interp: x})
			continue
		}
		start := p.pos
		for p.pos < len(p.src) && (isIdent(rune(p.src[p.pos])) || strings.ContainsRune("().-", rune(p.src[p.pos]))) {
			if p.src[p.pos] == ')' && !strings.Contains(p.src[start:p.pos], "(") {
				break
			}
			p.pos++
		}
		pe.parts = append(pe.parts, pathPart{literal: p.src[start:p.pos]})
	}
	return pe, nil
}
