extern crate zydis;
use zydis::{
    gen::{ZYDIS_ADDRESS_WIDTH_64, ZYDIS_FORMATTER_STYLE_INTEL, ZYDIS_MACHINE_MODE_LONG_64},
    *,
};

#[cfg_attr(rustfmt, rustfmt_skip)]
static CODE: &'static [u8] = &[
    0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75, 0x08,
    0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F, 0x88, 0xFC,
    0xDA, 0x02, 0x00u8,
];

fn main() -> Result<()> {
    let formatter = Formatter::new(ZYDIS_FORMATTER_STYLE_INTEL)?;
    let decoder = Decoder::new(ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64)?;

    for (instruction, ip) in decoder.instruction_iterator(CODE, 0) {
        let insn = formatter.format_instruction(&instruction, 200, ip, None)?;
        println!("0x{:016X} {}", ip, insn);
    }

    Ok(())
}