; example idsa function which logs all its arguments to /tmp

(define log-target (open-file "/tmp/idsaguile.log" "a0"))

(define idsa 
  (lambda (n)
    (begin 
      (display n log-target)
      (newline log-target)
      #t)))
