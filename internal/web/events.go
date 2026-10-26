// Modified in this fork: new file.

package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	pb "cloud.google.com/go/firestore/apiv1/firestorepb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/omelas-tech/kor/internal/auth"
	"github.com/omelas-tech/kor/internal/backend"
)

// serveEvents is GET /kor/v1/events?cursor=&limit=: committed document
// changes with before and after images, for event handlers. Admin only.
func (s *Server) serveEvents(w http.ResponseWriter, r *http.Request) {
	ctx, err := s.principal(r.Context(), auth.BearerToken(r.Header.Get("Authorization")))
	if err != nil {
		writeStatusError(w, err)
		return
	}
	if p := auth.FromContext(ctx); p == nil || !p.Admin {
		writeError(w, http.StatusForbidden, "PERMISSION_DENIED", "events are for backend services")
		return
	}
	log, ok := s.opts.Events.(backend.EventLog)
	if !ok || log == nil {
		writeError(w, http.StatusNotImplemented, "UNIMPLEMENTED", "this backend keeps no event log")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, cursor, err := log.ReadEvents(ctx, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	var buf bytes.Buffer
	buf.WriteString(`{"cursor":`)
	c, _ := json.Marshal(cursor)
	buf.Write(c)
	buf.WriteString(`,"events":[`)
	for i, e := range events {
		if i > 0 {
			buf.WriteByte(',')
		}
		head, _ := json.Marshal(map[string]any{
			"id": e.ID, "document": e.Name, "collectionId": e.CollectionID,
			"commitTime": e.CommitTime.UTC().Format(time.RFC3339Nano),
		})
		buf.Write(head[:len(head)-1])
		for _, img := range []struct {
			key string
			doc *backend.Doc
		}{{"before", e.Before}, {"after", e.After}} {
			buf.WriteString(`,"` + img.key + `":`)
			if img.doc == nil {
				buf.WriteString("null")
				continue
			}
			b, err := marshal.Marshal(&pb.Document{
				Name: img.doc.Name, Fields: img.doc.Fields,
				CreateTime: timestamppb.New(img.doc.CreateTime), UpdateTime: timestamppb.New(img.doc.UpdateTime),
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
				return
			}
			buf.Write(b)
		}
		buf.WriteByte('}')
	}
	buf.WriteString("]}")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}
