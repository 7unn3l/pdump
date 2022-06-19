use nix::libc::execve;
use nix::unistd::{fork,Pid, ForkResult};
use nix::sys::ptrace;
use std::env;
use std::ffi::CString;
use nix::sys::wait::waitpid;
use nix::sys::personality;
use nix::sys::personality::Persona;

fn child_setup(elf:&str){

    personality::set(Persona::ADDR_NO_RANDOMIZE).expect("setting persona did not work!");
    
    unsafe {
        // ouf

        let elf = CString::new(elf).unwrap();
        use std::ptr;
        use nix::libc::c_char;

        let argv: &[*const c_char] = &[elf.as_ptr(), elf.as_ptr(), ptr::null()];
        let envp: &[*const c_char] = &[ptr::null()];

        match ptrace::traceme(){
            Err(e) => print!("tracme error: {}",e.desc()),
            other => {}
        }

        // due to traceme(), we will stop at this execve
        execve(elf.as_ptr(),&argv[0],&envp[0]);
    }

    return;
}

fn search_elf_header(pid: Pid,entry_rip: u64){
    /*
    search until ELF header is found. Validate via
    signature and entrypoint
    */
    let mut addr: u64 = 0;
    loop{

        let result: i64 = match ptrace::read(pid,addr as *mut _){
            Ok(val) => val,
            Err(err) => 0
        };

        result.to_be();

        if result != 0{
            println!("YUH! : {:?}",result.to_le_bytes().from);
            break;
        }
        
        addr += 8;
    }

}

fn dump_child(pid:Pid){
    println!("dumping child with pid = {}",pid);
    
    match waitpid(pid,None){
        Ok(res) => {println!("ok: {:?}",res)},
        Err(err) => print!("errror while waitpid: {}",err.desc())
    }

    let current_rip: u64 = ptrace::getregs(pid).expect("could not get current rip value").rip;
    
    search_elf_header(pid,current_rip);

}

fn help(){
    println!("pdump <target_elf>");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String>  = env::args().collect();

    if env::args().count() < 2{
        help();
    }
    
    let target_elf = &args[1];

    println!("dumping {}",target_elf);

    match unsafe {fork()}{
        Ok(ForkResult::Child) => {child_setup(target_elf)},
        
        Ok(ForkResult::Parent{child,..}) => { dump_child(child) },
        
        Err(err) => { println!("could not fork: {}",err.desc()) }

    }

}
