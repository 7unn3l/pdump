use nix::libc::execve;
use nix::unistd::{fork,Pid, ForkResult};
use nix::sys::ptrace;
use std::env;
use std::ffi::CString;
use nix::sys::wait::waitpid;
use nix::sys::personality;
use nix::sys::personality::Persona;

enum Endianess{
    Big,
    Little
}

const MAGIC: [u8;4] = [0x7f,0x45,0x4c,0x46];

fn get_endianess() -> Endianess{
    let var :u16 = 1;

    if var as u8 == 1{
        return Endianess::Little;
    }
    return Endianess::Big;
}

fn child_setup(elf:&str){

    personality::set(Persona::ADDR_NO_RANDOMIZE).expect("setting persona did not work!");
    
    unsafe {
        // ouf

        let elf = CString::new(elf).unwrap();
        use std::ptr;
        use nix::libc::c_char;

        let argv: &[*const c_char] = &[elf.as_ptr(), elf.as_ptr(), ptr::null()];
        let envp: &[*const c_char] = &[ptr::null()];

        ptrace::traceme().expect("could not issue traceme!");

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

    let endianess =  get_endianess();

    let mut addr: u64 = 0;
    loop{
        let result: i64 = match ptrace::read(pid,addr as *mut _){
            Ok(val) => val,
            Err(_) => {
                // we might not be ata valid addr, skip this.
                addr += 8;
                continue;
            }
        };


        if result != 0{
            let result = match endianess{
                Endianess::Big => result.to_be_bytes(),
                Endianess::Little => result.to_le_bytes()
            };
            
            // todo: iterators, closures
            match result.windows(4).position(|window| window == MAGIC){
                Some(index) => println!("found at index {}, total addr is {}",index,addr+index as u64),
                None => {}
            }

            break;
        }
        
        addr += 8;
    }

}

fn dump_child(pid:Pid){
    println!("dumping child with pid = {}",pid);
    
    match waitpid(pid,None){
        Ok(res) => {println!("target binary stopped: {:?}",res)},
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
