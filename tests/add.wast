(module
  (type (;0;) (func))
  (type (;2;) (func (result i64)))
  (import "env" "ontio_timestamp" (func $ontio_timestamp (type 1)))
  (func $invoke (export "invoke") (type 0)
		call $ontio_timestamp
		drop
  )
)

