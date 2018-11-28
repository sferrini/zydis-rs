//! A completely stupid example for Zydis' formatter hook API.

#![deny(bare_trait_objects)]

extern crate zydis;

use std::{fmt::Write, mem, ptr};

use zydis::{check, *};

#[rustfmt::skip]
static CODE: &'static [u8] = &[
    // cmpps xmm1, xmm4, 0x03
    0x0F, 0xC2, 0xCC, 0x03,
    // vcmppd xmm1, xmm2, xmm3, 0x17
    0xC5, 0xE9, 0xC2, 0xCB, 0x17,
    // vcmpps k2 {k7}, zmm2, dword ptr ds:[rax + rbx*4 + 0x100] {1to16}, 0x0F
    0x62, 0xF1, 0x6C, 0x5F, 0xC2, 0x54, 0x98, 0x40, 0x0F
];

static CONDITION_CODES: &'static [&'static str] = &[
    "eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord", "eq_uq", "nge", "ngt", "false", "oq",
    "ge", "gt", "true", "eq_os", "lt_oq", "le_oq", "unord_s", "neq_us", "nlt_uq", "nle_uq",
    "ord_s", "eq_us", "nge_uq", "ngt_uq", "false_os", "neg_os", "ge_oq", "gt_oq", "true_us",
];

// Used with .map_err
fn user_err<T>(_: T) -> Status {
    Status::User
}

struct UserData {
    orig_print_mnemonic: FormatterFunc,
    orig_format_operand: FormatterFunc,
    omit_immediate: bool,
}

unsafe extern "C" fn print_mnemonic(
    formatter: *const Formatter,
    buffer: *mut FormatterBuffer,
    ctx: *mut FormatterContext,
) -> Status {
    let f = move || {
        let buffer = &mut *buffer;
        let ctx = &mut *ctx;
        let usr = &mut *(ctx.user_data as *mut UserData);

        let instruction = &*ctx.instruction;

        usr.omit_immediate = true;

        let count = instruction.operand_count as usize;

        if count > 0 && instruction.operands[count - 1].ty == OperandType::Immediate {
            let cc = instruction.operands[count - 1].imm.value as usize;

            match instruction.mnemonic {
                Mnemonic::CMPPS if cc < 8 => {
                    buffer.append(TOKEN_MNEMONIC)?;
                    let string = buffer.get_string()?;
                    return write!(string, "cmp{}ps", CONDITION_CODES[cc]).map_err(user_err);
                }
                Mnemonic::CMPPD if cc < 8 => {
                    buffer.append(TOKEN_MNEMONIC)?;
                    let string = buffer.get_string()?;
                    return write!(string, "cmp{}pd", CONDITION_CODES[cc]).map_err(user_err);
                }
                Mnemonic::VCMPPS if cc < 0x20 => {
                    buffer.append(TOKEN_MNEMONIC)?;
                    let string = buffer.get_string()?;
                    return write!(string, "vcmp{}ps", CONDITION_CODES[cc]).map_err(user_err);
                }
                Mnemonic::VCMPPD if cc < 0x20 => {
                    buffer.append(TOKEN_MNEMONIC)?;
                    let string = buffer.get_string()?;
                    return write!(string, "vcmp{}pd", CONDITION_CODES[cc]).map_err(user_err);
                }
                _ => {}
            }
        }

        usr.omit_immediate = false;
        check!((usr.orig_print_mnemonic.unwrap())(
            mem::transmute(formatter),
            buffer,
            ctx
        ))
    };

    match f() {
        Ok(_) => Status::Success,
        Err(e) => e,
    }
}

unsafe extern "C" fn format_operand_imm(
    formatter: *const Formatter,
    buffer: *mut FormatterBuffer,
    ctx: *mut FormatterContext,
) -> Status {
    let usr = &*((*ctx).user_data as *const UserData);
    if usr.omit_immediate {
        Status::SkipToken
    } else {
        (usr.orig_format_operand.unwrap())(formatter, buffer, ctx)
    }
}

fn main() -> Result<()> {
    let mut formatter = Formatter::new(FormatterStyle::Intel)?;
    formatter.set_property(FormatterProperty::ForceSegment(true))?;
    formatter.set_property(FormatterProperty::ForceSize(true))?;

    // clear old prefix
    formatter.set_property(FormatterProperty::HexPrefix(None))?;
    // set h as suffix
    formatter.set_property(FormatterProperty::HexSuffix(Some("h")))?;

    let decoder = Decoder::new(MachineMode::Long64, AddressWidth::_64)?;

    let mut buffer = [0u8; 200];
    let mut buffer = OutputBuffer::new(&mut buffer[..]);

    // First without hooks
    for (instruction, ip) in decoder.instruction_iterator(CODE, 0) {
        formatter.format_instruction(&instruction, &mut buffer, Some(ip), ptr::null_mut())?;
        println!("0x{:016X} {}", ip, buffer);
    }

    println!();

    // Now set the hooks
    let orig_print_mnemonic = if let Hook::PrintMnemonic(o) =
        formatter.set_hook(Hook::PrintMnemonic(Some(print_mnemonic)))?
    {
        o
    } else {
        unreachable!()
    };
    let orig_format_operand = if let Hook::FormatOperandImm(o) =
        formatter.set_hook(Hook::FormatOperandImm(Some(format_operand_imm)))?
    {
        o
    } else {
        unreachable!()
    };

    let mut user_data = UserData {
        orig_print_mnemonic,
        orig_format_operand,
        omit_immediate: false,
    };

    // And print it with hooks
    for (instruction, ip) in decoder.instruction_iterator(CODE, 0) {
        formatter.format_instruction(
            &instruction,
            &mut buffer,
            Some(ip),
            &mut user_data as *mut UserData as *mut _,
        )?;
        println!("0x{:016X} {}", ip, buffer);
    }

    Ok(())
}
