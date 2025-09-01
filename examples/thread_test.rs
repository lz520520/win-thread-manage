use std::thread;
use std::time::Duration;
use win_thread_manage::initialize_hooks;

fn main() {
    initialize_hooks();
    thread::spawn(||{
        println!("Thread started");
        thread::sleep(Duration::from_secs(1));
    });
    thread::sleep(Duration::from_secs(20));
    // get_current_thread_frames();
}