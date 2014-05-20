; example with trace enabled, idsa returns true (allows) all events

(transcript-on "/tmp/idsaguile.trace")
(define idsa (lambda (n) #t))
