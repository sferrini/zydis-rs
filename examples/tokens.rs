extern crate zydis;

use std::ptr;

use zydis::*;

#[rustfmt::skip]
static CODE: &'static [u8] = &[
    0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75, 0x08,
    0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F, 0x88, 0xFC,
    0xDA, 0x02, 0x00,
];

fn main() -> Result<()> {
    let decoder = Decoder::new(MachineMode::Long64, AddressWidth::_64)?;
    let formatter = Formatter::new(FormatterStyle::Intel)?;

    let mut buffer = [0u8; 256];

    for (instruction, ip) in decoder.instruction_iterator(CODE, 0) {
        for (ty, val) in formatter.tokenize_instruction(
            &instruction,
            &mut buffer[..],
            Some(ip),
            ptr::null_mut(),
        )? {
            println!("token type: {}, value: {}", ty, val);
        }
        println!("----");
    }

    Ok(())
}
