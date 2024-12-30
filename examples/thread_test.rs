use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE};
use thread_helper::thread::get_current_thread_frames;

fn main() {
    println!("{}",MEM_COMMIT.0 & (MEM_RESERVE.0) > 0);
    // get_current_thread_frames();
}