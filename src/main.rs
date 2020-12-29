//! ###############################################################################
//! # Coldsnap-rust is a "Hello World" example of a snapshot fuzzer built in rust #
//! ###############################################################################
//! 
//! Author: Evan Custodio
//! 
//! This executable is an example of a snapshot fuzzer written in rust. This is basically
//! a 1-to-1 port of my snapshot fuzzer written in python

fn main() {
    println!("coldsnap - A rust-based snapshot-based ptrace-based fuzzer example");
	println!("Author   - @defparam (Evan Custodio)\n");

	// First We fork our target
	let mut process = coldsnap::Target::new();
	
	// This function initializes fuzzer and snapshot state
	process.create_initial_state();
	
	println!("\nStarting Snapshot Fuzzer...\n");
	println!("Corpus discovery coverage growth:");
	
	loop {
		process.start_case();          // Count a new case
		process.fuzz();                // Create a fuzz mutation and apply it to target memory
		process.check_fuzz_result();   // See if the payload created new coverage or a crash
		process.rewind();              // rewind target state to the startf function
	}
}
