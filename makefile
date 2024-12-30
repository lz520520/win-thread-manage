

lib:
	cargo build --release --lib -p static_lib
	cp target/release/libstatic_lib.a ../../go/acc_agent/res/libwin_thread_manage.a
