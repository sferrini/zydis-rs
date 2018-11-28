extern crate zydis;

use zydis::{
    check, AddressWidth, Decoder, Formatter, FormatterBuffer, FormatterContext, FormatterFunc,
    FormatterProperty, FormatterStyle, Hook, MachineMode, OutputBuffer, Result as ZydisResult,
    Status, TOKEN_SYMBOL,
};

use std::{fmt::Write, mem};

#[rustfmt::skip]
const CODE: &'static [u8] = &[
    0x48, 0x8B, 0x05, 0x39, 0x00, 0x13, 0x00, // mov rax, qword ptr ds:[<SomeModule.SomeData>]
    0x50,                                     // push rax
    0xFF, 0x15, 0xF2, 0x10, 0x00, 0x00,       // call qword ptr ds:[<SomeModule.SomeFunction>]
    0x85, 0xC0,                               // test eax, eax
    0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,       // jz 0x007FFFFFFF400016
    0xE9, 0xE5, 0x0F, 0x00, 0x00              // jmp <SomeModule.EntryPoint>
];

const SYMBOL_TABLE: &'static [(u64, &'static str)] = &[
    (0x007FFFFFFF401000, "SomeModule.EntryPoint"),
    (0x007FFFFFFF530040, "SomeModule.SomeData"),
    (0x007FFFFFFF401100, "SomeModule.SomeFunction"),
];

unsafe extern "C" fn print_address(
    formatter: *const Formatter,
    buffer: *mut FormatterBuffer,
    context: *mut FormatterContext,
) -> Status {
    let f = move || {
        let buffer = &mut *buffer;
        let context = &mut *context;

        let addr = (*context.instruction)
            .calc_absolute_address(context.runtime_address, &*context.operand)?;

        match SYMBOL_TABLE.iter().find(|&&(x, _)| x == addr) {
            Some((_, symbol)) => {
                buffer.append(TOKEN_SYMBOL)?;
                write!(buffer.get_string()?, "<{}>", symbol).map_err(|_| Status::User)
            }
            None => check!(
                (mem::transmute::<_, FormatterFunc>(context.user_data).unwrap())(
                    formatter, buffer, context,
                ),
                ()
            ),
        }
    };

    match f() {
        Ok(_) => Status::Success,
        Err(e) => e,
    }
}

fn main() -> ZydisResult<()> {
    let decoder = Decoder::new(MachineMode::Long64, AddressWidth::_64)?;

    let mut formatter = Formatter::new(FormatterStyle::Intel)?;
    formatter.set_property(FormatterProperty::ForceSegment(true))?;
    formatter.set_property(FormatterProperty::ForceSize(true))?;

    let mut orig_print_address = if let Hook::PrintAddressAbs(x) =
        formatter.set_hook(Hook::PrintAddressAbs(Some(print_address)))?
    {
        x
    } else {
        unreachable!();
    };

    let runtime_address = 0x007FFFFFFF400000;

    let mut buffer = [0u8; 200];
    let mut buffer = OutputBuffer::new(&mut buffer[..]);

    for (instruction, ip) in decoder.instruction_iterator(CODE, runtime_address) {
        formatter.format_instruction(&instruction, &mut buffer, Some(ip), unsafe {
            mem::transmute(&mut orig_print_address)
        })?;

        println!("0x{:016X} {}", ip, buffer);
    }

    Ok(())
}
