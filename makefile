

lib:
	cargo build --release --lib -p static_lib
#	cp target/release/libstatic_lib.a ../accelerator-rust/c_helper/rdi_helper/lib/libwin_thread_manage.a
