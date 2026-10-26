// Modified in this fork: new file.

package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
)

// Value is a rules value: nil, bool, int64, float64, string, []byte,
// time.Time, []Value (list), map[string]Value (map), Path, *mapDiff.
type Value any

// Path is a document path relative to the service root, as segments.
type Path []string

type mapDiff struct{ a, b map[string]Value }

// Doc is a document as rules see it.
type Doc struct {
	Name   string // full resource name
	Fields map[string]*pb.Value
}

// Lookup reads documents for get() and exists(). It returns nil for a
// missing document.
type Lookup func(name string) (*Doc, error)

// Request describes one access to check.
type Request struct {
	// Method is get, list, create, update or delete.
	Method string
	// Name is the document's full resource name
	// (projects/{p}/databases/{d}/documents/...).
	Name string
	// Auth is nil for an unauthenticated request.
	Auth *Auth
	// Resource is the document before the request (nil when absent);
	// NewResource is the document after a write (nil for delete).
	Resource    *Doc
	NewResource *Doc
	Time        time.Time
	Lookup      Lookup
}

// Auth is request.auth.
type Auth struct {
	UID   string
	Token map[string]any
}

var errUndefined = errors.New("undefined")

// Allowed reports whether rs allows req. Any evaluation error denies.
func (rs *Ruleset) Allowed(req *Request) (bool, error) {
	parts := strings.Split(req.Name, "/")
	if len(parts) < 5 || parts[0] != "projects" || parts[2] != "databases" || parts[4] != "documents" {
		return false, fmt.Errorf("rules: bad document name %q", req.Name)
	}
	project, database := parts[1], parts[3]
	// The service's top-level matches see the path starting at /databases.
	rel := append([]string{"databases", database, "documents"}, parts[5:]...)
	ev := &evaluator{req: req, project: project, database: database}
	ev.request = ev.requestValue()
	root := &scope{functions: rs.root.functions, vars: map[string]Value{}}
	return ev.walk(rs.root.matches, rel, root), nil
}

type evaluator struct {
	req      *Request
	project  string
	database string
	request  Value
	depth    int
}

type scope struct {
	parent    *scope
	vars      map[string]Value
	functions map[string]*function
}

func (s *scope) lookupVar(name string) (Value, bool) {
	for c := s; c != nil; c = c.parent {
		if v, ok := c.vars[name]; ok {
			return v, true
		}
	}
	return nil, false
}

func (s *scope) lookupFunc(name string) (*function, *scope) {
	for c := s; c != nil; c = c.parent {
		if f, ok := c.functions[name]; ok {
			return f, c
		}
	}
	return nil, nil
}

// walk tries every match block against the remaining path. A block whose
// pattern consumes the whole path contributes its allow statements; nested
// blocks continue from what it consumed. Matches OR-combine.
func (ev *evaluator) walk(blocks []*block, rest []string, sc *scope) bool {
	for _, b := range blocks {
		vars, consumed, ok := matchPrefix(b.pattern, rest)
		if !ok {
			continue
		}
		child := &scope{parent: sc, vars: vars, functions: b.functions}
		if consumed == len(rest) {
			for _, a := range b.allows {
				if !allows(a.methods, ev.req.Method) {
					continue
				}
				if a.cond == nil {
					return true
				}
				v, err := ev.eval(a.cond, child)
				if err == nil && v == true {
					return true
				}
			}
		}
		if ev.walk(b.matches, rest[consumed:], child) {
			return true
		}
	}
	return false
}

func allows(methods []string, m string) bool {
	for _, x := range methods {
		switch {
		case x == m:
			return true
		case x == "read" && (m == "get" || m == "list"):
			return true
		case x == "write" && (m == "create" || m == "update" || m == "delete"):
			return true
		}
	}
	return false
}

// matchPrefix matches a pattern against the start of path. A recursive
// wildcard consumes everything left (zero or more segments).
func matchPrefix(pattern []segment, path []string) (map[string]Value, int, bool) {
	vars := map[string]Value{}
	i := 0
	for _, seg := range pattern {
		if seg.recursive {
			vars[seg.variable] = Path(append([]string(nil), path[i:]...))
			return vars, len(path), true
		}
		if i >= len(path) {
			return nil, 0, false
		}
		if seg.variable != "" {
			vars[seg.variable] = path[i]
		} else if seg.literal != path[i] {
			return nil, 0, false
		}
		i++
	}
	return vars, i, true
}

func (ev *evaluator) requestValue() Value {
	r := map[string]Value{
		"method": ev.req.Method,
		"time":   ev.req.Time,
		"path":   ev.docPath(ev.req.Name),
		"auth":   nil,
	}
	if a := ev.req.Auth; a != nil {
		r["auth"] = map[string]Value{"uid": a.UID, "token": jsonToValue(a.Token)}
	}
	if ev.req.NewResource != nil {
		r["resource"] = ev.resourceValue(ev.req.NewResource)
	} else {
		r["resource"] = nil
	}
	return r
}

func (ev *evaluator) resourceValue(d *Doc) Value {
	if d == nil {
		return nil
	}
	data := map[string]Value{}
	for k, v := range d.Fields {
		data[k] = fromProto(v)
	}
	parts := strings.Split(d.Name, "/")
	return map[string]Value{"data": data, "id": parts[len(parts)-1], "__name__": ev.docPath(d.Name)}
}

func (ev *evaluator) docPath(name string) Path {
	parts := strings.Split(name, "/")
	if len(parts) < 5 {
		return Path(parts)
	}
	return Path(append([]string{"databases", parts[3], "documents"}, parts[5:]...))
}

func (ev *evaluator) fullName(p Path) (string, error) {
	if len(p) < 3 || p[0] != "databases" || p[2] != "documents" {
		return "", fmt.Errorf("path %q is not a document path", "/"+strings.Join(p, "/"))
	}
	return "projects/" + ev.project + "/databases/" + p[1] + "/documents/" + strings.Join(p[3:], "/"), nil
}

const maxDepth = 64

func (ev *evaluator) eval(e expr, sc *scope) (Value, error) {
	ev.depth++
	defer func() { ev.depth-- }()
	if ev.depth > maxDepth {
		return nil, errors.New("expression too deep")
	}
	switch x := e.(type) {
	case *litExpr:
		return x.v, nil
	case *identExpr:
		switch x.name {
		case "request":
			return ev.request, nil
		case "resource":
			return ev.resourceValue(ev.req.Resource), nil
		case "database":
			if v, ok := sc.lookupVar("database"); ok {
				return v, nil
			}
			return ev.database, nil
		}
		if v, ok := sc.lookupVar(x.name); ok {
			return v, nil
		}
		switch x.name {
		case "hashing", "math", "string", "int", "float", "timestamp", "duration":
			return namespace(x.name), nil
		}
		return nil, fmt.Errorf("unknown variable %q", x.name)
	case *unaryExpr:
		v, err := ev.eval(x.x, sc)
		if err != nil {
			return nil, err
		}
		switch x.op {
		case "!":
			b, ok := v.(bool)
			if !ok {
				return nil, errors.New("! needs a bool")
			}
			return !b, nil
		default:
			switch n := v.(type) {
			case int64:
				return -n, nil
			case float64:
				return -n, nil
			}
			return nil, errors.New("- needs a number")
		}
	case *binaryExpr:
		return ev.binary(x, sc)
	case *isExpr:
		v, err := ev.eval(x.x, sc)
		if err != nil {
			return nil, err
		}
		return isType(v, x.kind), nil
	case *condExpr:
		c, err := ev.eval(x.c, sc)
		if err != nil {
			return nil, err
		}
		b, ok := c.(bool)
		if !ok {
			return nil, errors.New("condition is not a bool")
		}
		if b {
			return ev.eval(x.t, sc)
		}
		return ev.eval(x.f, sc)
	case *memberExpr:
		v, err := ev.eval(x.x, sc)
		if err != nil {
			return nil, err
		}
		return member(v, x.name)
	case *indexExpr:
		v, err := ev.eval(x.x, sc)
		if err != nil {
			return nil, err
		}
		i, err := ev.eval(x.i, sc)
		if err != nil {
			return nil, err
		}
		return index(v, i)
	case *callExpr:
		return ev.call(x, sc)
	case *listExpr:
		out := make([]Value, 0, len(x.items))
		for _, it := range x.items {
			v, err := ev.eval(it, sc)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case *mapExpr:
		out := map[string]Value{}
		for i, k := range x.keys {
			v, err := ev.eval(x.vals[i], sc)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case *pathExpr:
		var p Path
		for _, part := range x.parts {
			if part.interp == nil {
				p = append(p, part.literal)
				continue
			}
			v, err := ev.eval(part.interp, sc)
			if err != nil {
				return nil, err
			}
			switch t := v.(type) {
			case string:
				p = append(p, t)
			case Path:
				p = append(p, t...)
			default:
				return nil, fmt.Errorf("cannot interpolate %T into a path", v)
			}
		}
		return p, nil
	}
	return nil, fmt.Errorf("unknown expression %T", e)
}

func (ev *evaluator) binary(x *binaryExpr, sc *scope) (Value, error) {
	switch x.op {
	case "&&":
		l, lerr := ev.eval(x.l, sc)
		if lerr == nil && l == false {
			return false, nil
		}
		r, rerr := ev.eval(x.r, sc)
		if rerr == nil && r == false {
			return false, nil
		}
		if lerr != nil {
			return nil, lerr
		}
		if rerr != nil {
			return nil, rerr
		}
		lb, ok1 := l.(bool)
		rb, ok2 := r.(bool)
		if !ok1 || !ok2 {
			return nil, errors.New("&& needs bools")
		}
		return lb && rb, nil
	case "||":
		l, lerr := ev.eval(x.l, sc)
		if lerr == nil && l == true {
			return true, nil
		}
		r, rerr := ev.eval(x.r, sc)
		if rerr == nil && r == true {
			return true, nil
		}
		if lerr != nil {
			return nil, lerr
		}
		if rerr != nil {
			return nil, rerr
		}
		lb, ok1 := l.(bool)
		rb, ok2 := r.(bool)
		if !ok1 || !ok2 {
			return nil, errors.New("|| needs bools")
		}
		return lb || rb, nil
	}
	l, err := ev.eval(x.l, sc)
	if err != nil {
		return nil, err
	}
	r, err := ev.eval(x.r, sc)
	if err != nil {
		return nil, err
	}
	switch x.op {
	case "==":
		return equal(l, r), nil
	case "!=":
		return !equal(l, r), nil
	case "<", "<=", ">", ">=":
		c, err := compare(l, r)
		if err != nil {
			return nil, err
		}
		switch x.op {
		case "<":
			return c < 0, nil
		case "<=":
			return c <= 0, nil
		case ">":
			return c > 0, nil
		default:
			return c >= 0, nil
		}
	case "in":
		switch coll := r.(type) {
		case []Value:
			for _, it := range coll {
				if equal(l, it) {
					return true, nil
				}
			}
			return false, nil
		case map[string]Value:
			k, ok := l.(string)
			if !ok {
				return nil, errors.New("map keys are strings")
			}
			_, ok = coll[k]
			return ok, nil
		}
		return nil, errors.New("in needs a list or map")
	case "+":
		switch a := l.(type) {
		case string:
			if b, ok := r.(string); ok {
				return a + b, nil
			}
		case []Value:
			if b, ok := r.([]Value); ok {
				return append(append([]Value{}, a...), b...), nil
			}
		}
		return arith(x.op, l, r)
	default:
		return arith(x.op, l, r)
	}
}

func arith(op string, l, r Value) (Value, error) {
	li, lInt := l.(int64)
	ri, rInt := r.(int64)
	if lInt && rInt {
		switch op {
		case "+":
			return li + ri, nil
		case "-":
			return li - ri, nil
		case "*":
			return li * ri, nil
		case "/":
			if ri == 0 {
				return nil, errors.New("division by zero")
			}
			return li / ri, nil
		case "%":
			if ri == 0 {
				return nil, errors.New("division by zero")
			}
			return li % ri, nil
		}
	}
	lf, ok1 := toFloat(l)
	rf, ok2 := toFloat(r)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("%s needs numbers", op)
	}
	switch op {
	case "+":
		return lf + rf, nil
	case "-":
		return lf - rf, nil
	case "*":
		return lf * rf, nil
	case "/":
		return lf / rf, nil
	case "%":
		return math.Mod(lf, rf), nil
	}
	return nil, fmt.Errorf("unknown operator %s", op)
}

func toFloat(v Value) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func equal(a, b Value) bool {
	if af, ok := toFloat(a); ok {
		bf, ok := toFloat(b)
		return ok && af == bf
	}
	switch x := a.(type) {
	case time.Time:
		y, ok := b.(time.Time)
		return ok && x.Equal(y)
	case Path:
		y, ok := b.(Path)
		return ok && strings.Join(x, "/") == strings.Join(y, "/")
	}
	return reflect.DeepEqual(a, b)
}

func compare(a, b Value) (int, error) {
	if af, ok := toFloat(a); ok {
		if bf, ok := toFloat(b); ok {
			switch {
			case af < bf:
				return -1, nil
			case af > bf:
				return 1, nil
			}
			return 0, nil
		}
	}
	switch x := a.(type) {
	case string:
		if y, ok := b.(string); ok {
			return strings.Compare(x, y), nil
		}
	case time.Time:
		if y, ok := b.(time.Time); ok {
			return x.Compare(y), nil
		}
	}
	return 0, fmt.Errorf("cannot compare %T and %T", a, b)
}

func isType(v Value, kind string) bool {
	switch kind {
	case "string":
		_, ok := v.(string)
		return ok
	case "int":
		_, ok := v.(int64)
		return ok
	case "float":
		_, ok := v.(float64)
		return ok
	case "number":
		_, ok := toFloat(v)
		return ok
	case "bool":
		_, ok := v.(bool)
		return ok
	case "map":
		_, ok := v.(map[string]Value)
		return ok
	case "list":
		_, ok := v.([]Value)
		return ok
	case "timestamp":
		_, ok := v.(time.Time)
		return ok
	case "path":
		_, ok := v.(Path)
		return ok
	case "bytes":
		_, ok := v.([]byte)
		return ok
	case "null":
		return v == nil
	}
	return false
}

func member(v Value, name string) (Value, error) {
	switch m := v.(type) {
	case map[string]Value:
		if x, ok := m[name]; ok {
			return x, nil
		}
		return nil, fmt.Errorf("no field %q: %w", name, errUndefined)
	case nil:
		return nil, fmt.Errorf("field %q of null", name)
	}
	return nil, fmt.Errorf("cannot read field %q of %T", name, v)
}

func index(v, i Value) (Value, error) {
	switch c := v.(type) {
	case map[string]Value:
		k, ok := i.(string)
		if !ok {
			return nil, errors.New("map index must be a string")
		}
		if x, ok := c[k]; ok {
			return x, nil
		}
		return nil, fmt.Errorf("no key %q", k)
	case []Value:
		n, ok := i.(int64)
		if !ok || n < 0 || int(n) >= len(c) {
			return nil, errors.New("list index out of range")
		}
		return c[n], nil
	case Path:
		n, ok := i.(int64)
		if !ok || n < 0 || int(n) >= len(c) {
			return nil, errors.New("path index out of range")
		}
		return c[n], nil
	}
	return nil, fmt.Errorf("cannot index %T", v)
}

type namespace string

func (ev *evaluator) call(c *callExpr, sc *scope) (Value, error) {
	args := make([]Value, len(c.args))
	for i, a := range c.args {
		v, err := ev.eval(a, sc)
		if err != nil {
			return nil, err
		}
		args[i] = v
	}
	switch fn := c.fn.(type) {
	case *identExpr:
		switch fn.name {
		case "get", "exists", "getAfter", "existsAfter":
			return ev.docFunc(fn.name, args)
		}
		f, defScope := sc.lookupFunc(fn.name)
		if f == nil {
			return nil, fmt.Errorf("unknown function %q", fn.name)
		}
		if len(args) != len(f.params) {
			return nil, fmt.Errorf("%s takes %d arguments", fn.name, len(f.params))
		}
		local := &scope{parent: defScope, vars: map[string]Value{}}
		for i, p := range f.params {
			local.vars[p] = args[i]
		}
		for _, l := range f.lets {
			v, err := ev.eval(l.val, local)
			if err != nil {
				return nil, err
			}
			local.vars[l.name] = v
		}
		return ev.eval(f.body, local)
	case *memberExpr:
		recv, err := ev.eval(fn.x, sc)
		if err != nil {
			return nil, err
		}
		return method(recv, fn.name, args)
	}
	return nil, errors.New("not callable")
}

func (ev *evaluator) docFunc(name string, args []Value) (Value, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("%s takes one path", name)
	}
	p, ok := args[0].(Path)
	if !ok {
		return nil, fmt.Errorf("%s needs a path", name)
	}
	full, err := ev.fullName(p)
	if err != nil {
		return nil, err
	}
	var d *Doc
	if (name == "getAfter" || name == "existsAfter") && full == ev.req.Name {
		d = ev.req.NewResource
	} else if ev.req.Lookup != nil {
		if d, err = ev.req.Lookup(full); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(name, "exists") {
		return d != nil, nil
	}
	if d == nil {
		return nil, fmt.Errorf("document %s does not exist", full)
	}
	return ev.resourceValue(d), nil
}

func method(recv Value, name string, args []Value) (Value, error) {
	switch r := recv.(type) {
	case namespace:
		return namespaceCall(r, name, args)
	case map[string]Value:
		return mapMethod(r, name, args)
	case []Value:
		return listMethod(r, name, args)
	case string:
		return stringMethod(r, name, args)
	case []byte:
		switch name {
		case "toHexString":
			return strings.ToUpper(hex.EncodeToString(r)), nil
		case "size":
			return int64(len(r)), nil
		}
	case *mapDiff:
		return diffMethod(r, name)
	case Path:
		if name == "size" {
			return int64(len(r)), nil
		}
	}
	return nil, fmt.Errorf("no method %s on %T", name, recv)
}

func namespaceCall(ns namespace, name string, args []Value) (Value, error) {
	switch {
	case ns == "hashing" && (name == "sha256") && len(args) == 1:
		var data []byte
		switch v := args[0].(type) {
		case string:
			data = []byte(v)
		case []byte:
			data = v
		default:
			return nil, errors.New("hashing.sha256 needs a string or bytes")
		}
		sum := sha256.Sum256(data)
		return sum[:], nil
	case ns == "math" && name == "abs" && len(args) == 1:
		switch v := args[0].(type) {
		case int64:
			if v < 0 {
				return -v, nil
			}
			return v, nil
		case float64:
			return math.Abs(v), nil
		}
	}
	return nil, fmt.Errorf("unknown function %s.%s", ns, name)
}

func keysOf(m map[string]Value) []Value {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	out := make([]Value, len(ks))
	for i, k := range ks {
		out[i] = k
	}
	return out
}

func mapMethod(m map[string]Value, name string, args []Value) (Value, error) {
	switch name {
	case "keys":
		return keysOf(m), nil
	case "values":
		out := []Value{}
		for _, k := range keysOf(m) {
			out = append(out, m[k.(string)])
		}
		return out, nil
	case "size":
		return int64(len(m)), nil
	case "get":
		if len(args) != 2 {
			return nil, errors.New("map.get takes a key and a default")
		}
		switch k := args[0].(type) {
		case string:
			if v, ok := m[k]; ok {
				return v, nil
			}
			return args[1], nil
		case []Value:
			cur := Value(m)
			for _, part := range k {
				cm, ok := cur.(map[string]Value)
				ks, ok2 := part.(string)
				if !ok || !ok2 {
					return args[1], nil
				}
				if cur, ok = cm[ks]; !ok {
					return args[1], nil
				}
			}
			return cur, nil
		}
		return nil, errors.New("map.get key must be a string or list")
	case "diff":
		if len(args) != 1 {
			return nil, errors.New("map.diff takes a map")
		}
		other, ok := args[0].(map[string]Value)
		if !ok {
			return nil, errors.New("map.diff takes a map")
		}
		return &mapDiff{a: m, b: other}, nil
	case "hasAll", "hasAny", "hasOnly":
		return listMethod(keysOf(m), name, args)
	}
	return nil, fmt.Errorf("no map method %s", name)
}

func diffMethod(d *mapDiff, name string) (Value, error) {
	var out []Value
	add := func(k string) { out = append(out, k) }
	keys := map[string]bool{}
	for k := range d.a {
		keys[k] = true
	}
	for k := range d.b {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		av, inA := d.a[k]
		bv, inB := d.b[k]
		switch name {
		case "addedKeys":
			if inA && !inB {
				add(k)
			}
		case "removedKeys":
			if !inA && inB {
				add(k)
			}
		case "changedKeys":
			if inA && inB && !equal(av, bv) {
				add(k)
			}
		case "unchangedKeys":
			if inA && inB && equal(av, bv) {
				add(k)
			}
		case "affectedKeys":
			if !inA || !inB || !equal(av, bv) {
				add(k)
			}
		default:
			return nil, fmt.Errorf("no map diff method %s", name)
		}
	}
	if out == nil {
		out = []Value{}
	}
	return out, nil
}

func listMethod(l []Value, name string, args []Value) (Value, error) {
	contains := func(v Value) bool {
		for _, x := range l {
			if equal(x, v) {
				return true
			}
		}
		return false
	}
	arg := func() ([]Value, error) {
		if len(args) != 1 {
			return nil, fmt.Errorf("list.%s takes a list", name)
		}
		other, ok := args[0].([]Value)
		if !ok {
			return nil, fmt.Errorf("list.%s takes a list", name)
		}
		return other, nil
	}
	switch name {
	case "size":
		return int64(len(l)), nil
	case "toSet":
		return l, nil
	case "hasAll":
		other, err := arg()
		if err != nil {
			return nil, err
		}
		for _, x := range other {
			if !contains(x) {
				return false, nil
			}
		}
		return true, nil
	case "hasAny":
		other, err := arg()
		if err != nil {
			return nil, err
		}
		for _, x := range other {
			if contains(x) {
				return true, nil
			}
		}
		return false, nil
	case "hasOnly":
		other, err := arg()
		if err != nil {
			return nil, err
		}
		for _, x := range l {
			found := false
			for _, y := range other {
				if equal(x, y) {
					found = true
					break
				}
			}
			if !found {
				return false, nil
			}
		}
		return true, nil
	case "join":
		sep := ""
		if len(args) == 1 {
			sep, _ = args[0].(string)
		}
		parts := make([]string, 0, len(l))
		for _, x := range l {
			s, ok := x.(string)
			if !ok {
				return nil, errors.New("join needs strings")
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, sep), nil
	}
	return nil, fmt.Errorf("no list method %s", name)
}

func stringMethod(s, name string, args []Value) (Value, error) {
	switch name {
	case "lower":
		return strings.ToLower(s), nil
	case "upper":
		return strings.ToUpper(s), nil
	case "size":
		return int64(len([]rune(s))), nil
	case "trim":
		return strings.TrimSpace(s), nil
	case "matches":
		if len(args) == 1 {
			if pat, ok := args[0].(string); ok {
				re, err := regexp.Compile("^(?:" + pat + ")$")
				if err != nil {
					return nil, err
				}
				return re.MatchString(s), nil
			}
		}
	case "split":
		if len(args) == 1 {
			if sep, ok := args[0].(string); ok {
				out := []Value{}
				for _, p := range regexp.MustCompile(sep).Split(s, -1) {
					out = append(out, p)
				}
				return out, nil
			}
		}
	case "replace":
		if len(args) == 2 {
			pat, ok1 := args[0].(string)
			repl, ok2 := args[1].(string)
			if ok1 && ok2 {
				re, err := regexp.Compile(pat)
				if err != nil {
					return nil, err
				}
				return re.ReplaceAllString(s, repl), nil
			}
		}
	}
	return nil, fmt.Errorf("no string method %s", name)
}

// fromProto converts a stored Firestore value for rules.
func fromProto(v *pb.Value) Value {
	switch t := v.GetValueType().(type) {
	case *pb.Value_NullValue:
		return nil
	case *pb.Value_BooleanValue:
		return t.BooleanValue
	case *pb.Value_IntegerValue:
		return t.IntegerValue
	case *pb.Value_DoubleValue:
		return t.DoubleValue
	case *pb.Value_TimestampValue:
		return t.TimestampValue.AsTime()
	case *pb.Value_StringValue:
		return t.StringValue
	case *pb.Value_BytesValue:
		return t.BytesValue
	case *pb.Value_ReferenceValue:
		parts := strings.Split(t.ReferenceValue, "/")
		if len(parts) >= 5 {
			return Path(append([]string{"databases", parts[3], "documents"}, parts[5:]...))
		}
		return Path(parts)
	case *pb.Value_GeoPointValue:
		return map[string]Value{"latitude": t.GeoPointValue.GetLatitude(), "longitude": t.GeoPointValue.GetLongitude()}
	case *pb.Value_ArrayValue:
		out := make([]Value, 0, len(t.ArrayValue.GetValues()))
		for _, x := range t.ArrayValue.GetValues() {
			out = append(out, fromProto(x))
		}
		return out
	case *pb.Value_MapValue:
		out := map[string]Value{}
		for k, x := range t.MapValue.GetFields() {
			out[k] = fromProto(x)
		}
		return out
	}
	return nil
}

// jsonToValue converts decoded JWT claims for request.auth.token.
func jsonToValue(v any) Value {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]Value{}
		for k, x := range t {
			out[k] = jsonToValue(x)
		}
		return out
	case []any:
		out := make([]Value, len(t))
		for i, x := range t {
			out[i] = jsonToValue(x)
		}
		return out
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1<<53 {
			return int64(t)
		}
		return t
	default:
		return t
	}
}
