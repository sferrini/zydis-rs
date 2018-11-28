//! Textual instruction formatting routines.

use core::{ffi::c_void, fmt, marker::PhantomData, mem};

use crate::{
    enums::*,
    ffi::*,
    status::{Result, Status},
};

#[derive(Clone)]
pub enum Hook {
    PreInstruction(FormatterFunc),
    PostInstruction(FormatterFunc),
    PreOperand(FormatterFunc),
    PostOperand(FormatterFunc),
    FormatInstruction(FormatterFunc),
    FormatOperandReg(FormatterFunc),
    FormatOperandMem(FormatterFunc),
    FormatOperandPtr(FormatterFunc),
    FormatOperandImm(FormatterFunc),
    PrintMnemonic(FormatterFunc),
    PrintRegister(FormatterRegisterFunc),
    PrintAddressAbs(FormatterFunc),
    PrintAddressRel(FormatterFunc),
    PrintDisp(FormatterFunc),
    PrintImm(FormatterFunc),
    PrintTypecast(FormatterFunc),
    PrintPrefixes(FormatterFunc),
    PrintDecorator(FormatterDecoratorFunc),
}

impl Hook {
    #[rustfmt::skip]
    pub fn to_id(&self) -> HookType {
        use self::Hook::*;
        match self {
            PreInstruction(_)    => HookType::PRE_INSTRUCTION,
            PostInstruction(_)   => HookType::POST_INSTRUCTION,
            PreOperand(_)        => HookType::PRE_OPERAND,
            PostOperand(_)       => HookType::POST_OPERAND,
            FormatInstruction(_) => HookType::FORMAT_INSTRUCTION,
            FormatOperandReg(_)  => HookType::FORMAT_OPERAND_REG,
            FormatOperandMem(_)  => HookType::FORMAT_OPERAND_MEM,
            FormatOperandPtr(_)  => HookType::FORMAT_OPERAND_PTR,
            FormatOperandImm(_)  => HookType::FORMAT_OPERAND_IMM,
            PrintMnemonic(_)     => HookType::PRINT_MNEMONIC,
            PrintRegister(_)     => HookType::PRINT_REGISTER,
            PrintAddressAbs(_)   => HookType::PRINT_ADDRESS_ABS,
            PrintAddressRel(_)   => HookType::PRINT_ADDRESS_REL,
            PrintDisp(_)         => HookType::PRINT_DISP,
            PrintImm(_)          => HookType::PRINT_IMM,
            PrintTypecast(_)     => HookType::PRINT_TYPECAST,
            PrintPrefixes(_)     => HookType::PRINT_PREFIXES,
            PrintDecorator(_)    => HookType::PRINT_DECORATOR,
        }
    }

    pub unsafe fn to_raw(&self) -> *const c_void {
        use self::Hook::*;
        // Note: do not remove the `*` at `*self`, Rust 1.26 will segfault
        // since we don't give explicit types for mem::transmute.
        match *self {
            PreInstruction(x) | PostInstruction(x) | PrintPrefixes(x) | FormatInstruction(x)
            | PrintMnemonic(x) | PreOperand(x) | PostOperand(x) | FormatOperandReg(x)
            | FormatOperandMem(x) | FormatOperandPtr(x) | FormatOperandImm(x)
            | PrintAddressAbs(x) | PrintAddressRel(x) | PrintDisp(x) | PrintImm(x)
            | PrintTypecast(x) => mem::transmute(x),

            PrintRegister(x) => mem::transmute(x),
            PrintDecorator(x) => mem::transmute(x),
        }
    }

    #[rustfmt::skip]
    pub unsafe fn from_raw(id: HookType, cb: *const c_void) -> Hook {
        use self::Hook::*;
        match id {
            HookType::PRE_INSTRUCTION    => PreInstruction(mem::transmute(cb)),
            HookType::POST_INSTRUCTION   => PostInstruction(mem::transmute(cb)),
            HookType::FORMAT_INSTRUCTION => FormatInstruction(mem::transmute(cb)),
            HookType::PRE_OPERAND        => PreOperand(mem::transmute(cb)),
            HookType::POST_OPERAND       => PostOperand(mem::transmute(cb)),
            HookType::FORMAT_OPERAND_REG => FormatOperandReg(mem::transmute(cb)),
            HookType::FORMAT_OPERAND_MEM => FormatOperandMem(mem::transmute(cb)),
            HookType::FORMAT_OPERAND_PTR => FormatOperandPtr(mem::transmute(cb)),
            HookType::FORMAT_OPERAND_IMM => FormatOperandImm(mem::transmute(cb)),
            HookType::PRINT_MNEMONIC     => PrintMnemonic(mem::transmute(cb)),
            HookType::PRINT_REGISTER     => PrintRegister(mem::transmute(cb)),
            HookType::PRINT_ADDRESS_ABS  => PrintAddressAbs(mem::transmute(cb)),
            HookType::PRINT_ADDRESS_REL  => PrintAddressRel(mem::transmute(cb)),
            HookType::PRINT_DISP         => PrintDisp(mem::transmute(cb)),
            HookType::PRINT_IMM          => PrintImm(mem::transmute(cb)),
            HookType::PRINT_TYPECAST     => PrintTypecast(mem::transmute(cb)),
            HookType::PRINT_PREFIXES     => PrintPrefixes(mem::transmute(cb)),
            HookType::PRINT_DECORATOR    => PrintDecorator(mem::transmute(cb)),
        }
    }
}

#[derive(Clone, Copy)]
pub enum FormatterProperty<'a> {
    ForceSize(bool),
    ForceSegment(bool),
    ForceRelativeBranches(bool),
    ForceRelativeRiprel(bool),
    PrintBranchSize(bool),
    DetailedPrefixes(bool),
    AddressBase(NumericBase),
    AddressSignedness(Signedness),
    AddressPaddingAbsolute(Padding),
    AddressPaddingRelative(Padding),
    DisplacementBase(NumericBase),
    DisplacementSignedness(Signedness),
    DisplacementPadding(Padding),
    ImmediateBase(NumericBase),
    ImmediateSignedness(Signedness),
    ImmediatePadding(Padding),
    UppercasePrefixes(bool),
    UppercaseMnemonic(bool),
    UppercaseRegisters(bool),
    UppercaseTypecasts(bool),
    UppercaseDecorators(bool),
    DecPrefix(Option<&'a str>),
    DecSuffix(Option<&'a str>),
    HexUppercase(bool),
    HexPrefix(Option<&'a str>),
    HexSuffix(Option<&'a str>),
}

fn ip_to_runtime_addr(ip: Option<u64>) -> u64 {
    match ip {
        None => (-1i64) as u64,
        Some(ip) => ip,
    }
}

/// A convenience typed when using the `format.*` or `tokenize.*` functions.
#[derive(Debug)]
pub struct OutputBuffer<'a> {
    pub buffer: &'a mut [u8],
}

impl<'a> OutputBuffer<'a> {
    /// Creates a new `OutputBuffer` using the given `buffer` for storage.
    #[inline]
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer }
    }

    /// Gets a string from this buffer.
    #[inline]
    pub fn as_str(&self) -> Result<&'a str> {
        unsafe { crate::ffi::str_from_c_str(self.buffer.as_ptr()) }
    }
}

impl<'a> fmt::Display for OutputBuffer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = self.as_str().map_err(|_| fmt::Error)?;
        write!(f, "{}", str)
    }
}

#[rustfmt::skip]
pub type FormatterFunc = Option<unsafe extern "C" fn(
    *const Formatter,
    *mut FormatterBuffer,
    *mut FormatterContext) -> Status>;

#[rustfmt::skip]
pub type FormatterDecoratorFunc = Option<unsafe extern "C" fn(
    *const Formatter,
    *mut FormatterBuffer,
    *mut FormatterContext,
    Decorator) -> Status>;

#[rustfmt::skip]
pub type FormatterRegisterFunc = Option<unsafe extern "C" fn(
    *const Formatter,
    *mut FormatterBuffer,
    *mut FormatterContext,
    Register) -> Status>;

#[repr(C)]
pub struct Formatter<'a> {
    style: FormatterStyle,
    force_memory_size: bool,
    force_memory_segment: bool,
    force_relative_branches: bool,
    force_relative_riprel: bool,
    print_branch_size: bool,
    detailed_prefixes: bool,
    addr_base: NumericBase,
    addr_signedness: Signedness,
    addr_padding_absolute: Padding,
    addr_padding_relative: Padding,
    disp_base: NumericBase,
    disp_signedness: Signedness,
    disp_padding: Padding,
    imm_base: NumericBase,
    imm_signedness: Signedness,
    imm_padding: Padding,
    case_prefixes: i32,
    case_mnemonic: i32,
    case_registers: i32,
    case_typecasts: i32,
    case_decorators: i32,
    hex_uppercase: bool,
    // ZYDIS_NUMERIC_BASE_MAX_VALUE + 1
    number_format: [[ZydisFormatterStringData; 2]; 2],

    func_pre_instruction: FormatterFunc,
    func_post_instruction: FormatterFunc,
    func_format_instruction: FormatterFunc,
    func_pre_operand: FormatterFunc,
    func_post_operand: FormatterFunc,
    func_format_operand_reg: FormatterFunc,
    func_format_operand_mem: FormatterFunc,
    func_format_operand_ptr: FormatterFunc,
    func_format_operand_imm: FormatterFunc,
    func_print_mnemonic: FormatterFunc,
    func_print_register: FormatterRegisterFunc,
    func_print_address_abs: FormatterFunc,
    func_print_address_rel: FormatterFunc,
    func_print_disp: FormatterFunc,
    func_print_imm: FormatterFunc,
    func_print_typecast: FormatterFunc,
    func_print_segment: FormatterFunc,
    func_print_prefixes: FormatterFunc,
    func_print_decorator: FormatterDecoratorFunc,

    _p: PhantomData<&'a ()>,
}

impl<'a> Formatter<'a> {
    /// Creates a new formatter instance.
    pub fn new(style: FormatterStyle) -> Result<Self> {
        unsafe {
            let mut formatter = mem::uninitialized();
            check!(ZydisFormatterInit(&mut formatter, style as _,), formatter)
        }
    }

    /// Sets the given FormatterProperty on this formatter instance.
    #[rustfmt::skip]
    pub fn set_property(&mut self, prop: FormatterProperty<'a>) -> Result<()> {
        use FormatterProperty::*;
        let (property, value) = match prop {
            ForceSize(v)              => (ZydisFormatterProperty::FORCE_SIZE              , v as usize),
            ForceSegment(v)           => (ZydisFormatterProperty::FORCE_SEGMENT           , v as usize),
            ForceRelativeBranches(v)  => (ZydisFormatterProperty::FORCE_RELATIVE_BRANCHES , v as usize),
            ForceRelativeRiprel(v)    => (ZydisFormatterProperty::FORCE_RELATIVE_RIPREL   , v as usize),
            PrintBranchSize(v)        => (ZydisFormatterProperty::PRINT_BRANCH_SIZE       , v as usize),
            DetailedPrefixes(v)       => (ZydisFormatterProperty::DETAILED_PREFIXES       , v as usize),
            AddressBase(v)            => (ZydisFormatterProperty::ADDR_BASE               , v as usize),
            AddressSignedness(v)      => (ZydisFormatterProperty::ADDR_SIGNEDNESS         , v as usize),
            AddressPaddingAbsolute(v) => (ZydisFormatterProperty::ADDR_PADDING_ABSOLUTE   , v as usize),
            AddressPaddingRelative(v) => (ZydisFormatterProperty::ADDR_PADDING_RELATIVE   , v as usize),
            DisplacementBase(v)       => (ZydisFormatterProperty::DISP_BASE               , v as usize),
            DisplacementSignedness(v) => (ZydisFormatterProperty::DISP_SIGNEDNESS         , v as usize),
            DisplacementPadding(v)    => (ZydisFormatterProperty::DISP_PADDING            , v as usize),
            ImmediateBase(v)          => (ZydisFormatterProperty::IMM_BASE                , v as usize),
            ImmediateSignedness(v)    => (ZydisFormatterProperty::IMM_SIGNEDNESS          , v as usize),
            ImmediatePadding(v)       => (ZydisFormatterProperty::IMM_PADDING             , v as usize),
            UppercasePrefixes(v)      => (ZydisFormatterProperty::UPPERCASE_PREFIXES      , v as usize),
            UppercaseMnemonic(v)      => (ZydisFormatterProperty::UPPERCASE_MNEMONIC      , v as usize),
            UppercaseRegisters(v)     => (ZydisFormatterProperty::UPPERCASE_REGISTERS     , v as usize),
            UppercaseTypecasts(v)     => (ZydisFormatterProperty::UPPERCASE_TYPECASTS     , v as usize),
            UppercaseDecorators(v)    => (ZydisFormatterProperty::UPPERCASE_DECORATORS    , v as usize),
            HexUppercase(v)           => (ZydisFormatterProperty::HEX_UPPERCASE           , v as usize),
            // The zydis API doesn't let us pass non zero terminated strings, so we modify the
            // internal string view directly.
            DecPrefix(x) => {
                self.number_format[0][0].set_data(x.unwrap_or(""));
                return Ok(());
            }
            DecSuffix(x) => {
                self.number_format[0][1].set_data(x.unwrap_or(""));
                return Ok(());
            }
            HexPrefix(x) => {
                self.number_format[1][0].set_data(x.unwrap_or(""));
                return Ok(());
            }
            HexSuffix(x) => {
                self.number_format[1][1].set_data(x.unwrap_or(""));
                return Ok(());
            }
        };

        unsafe {
            check!(ZydisFormatterSetProperty(
                self,
                property,
                value
            ))
        }
    }

    /// Formats the given `instruction`, using the given `buffer` for storage.
    ///
    /// The `ip` may be `None`, in which case relative address formatting is
    /// used. Otherwise absolute addresses are used.
    ///
    /// `user_data` may contain any data you wish to pass on to the
    /// Formatter hooks.
    ///
    /// # Examples
    /// ```
    /// use std::ptr;
    ///
    /// use zydis::{AddressWidth, Decoder, Formatter, FormatterStyle, MachineMode, OutputBuffer};
    /// static INT3: &'static [u8] = &[0xCCu8];
    ///
    /// let mut buffer = vec![0; 200];
    /// let mut buffer = OutputBuffer::new(&mut buffer[..]);
    ///
    /// let formatter = Formatter::new(FormatterStyle::Intel).unwrap();
    /// let dec = Decoder::new(MachineMode::Long64, AddressWidth::_64).unwrap();
    ///
    /// let info = dec.decode(INT3).unwrap().unwrap();
    /// formatter
    ///     .format_instruction(&info, &mut buffer, Some(0), ptr::null_mut())
    ///     .unwrap();
    /// assert_eq!(buffer.as_str().unwrap(), "int3");
    /// ```
    pub fn format_instruction(
        &self,
        instruction: &DecodedInstruction,
        buffer: &mut OutputBuffer,
        ip: Option<u64>,
        user_data: *mut c_void,
    ) -> Result<()> {
        unsafe {
            check!(ZydisFormatterFormatInstructionEx(
                self,
                instruction,
                buffer.buffer.as_mut_ptr() as *mut _,
                buffer.buffer.len(),
                ip_to_runtime_addr(ip),
                user_data,
            ))
        }
    }

    /// Formats just the given operand at `operand_index` from the given
    /// `instruction`, using `buffer` for storage.
    ///
    /// The `ip` may be `None`, in which case relative address formatting is
    /// used. Otherwise absolute addresses are used.
    ///
    /// `user_data` may contain any data you wish to pass on to the Formatter
    /// hooks.
    pub fn format_operand(
        &self,
        instruction: &DecodedInstruction,
        operand_index: u8,
        buffer: &mut OutputBuffer,
        ip: Option<u64>,
        user_data: *mut c_void,
    ) -> Result<()> {
        unsafe {
            check!(ZydisFormatterFormatOperandEx(
                self,
                instruction,
                operand_index,
                buffer.buffer.as_mut_ptr() as *mut _,
                buffer.buffer.len(),
                ip_to_runtime_addr(ip),
                user_data,
            ))
        }
    }

    /// The recommended amount of memory to allocate is 256 bytes.
    pub fn tokenize_instruction<'b>(
        &self,
        instruction: &DecodedInstruction,
        buffer: &'b mut [u8],
        ip: Option<u64>,
        user_data: *mut c_void,
    ) -> Result<&'b FormatterToken<'b>> {
        unsafe {
            let mut token = mem::uninitialized();
            check!(
                ZydisFormatterTokenizeInstructionEx(
                    self,
                    instruction,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len(),
                    ip_to_runtime_addr(ip),
                    &mut token,
                    user_data,
                ),
                &*token
            )
        }
    }

    /// Tokenizes the given operand at the `index` of the given `instruction`.
    pub fn tokenize_operand<'b>(
        &self,
        instruction: &DecodedInstruction,
        index: u8,
        buffer: &'b mut [u8],
        ip: Option<u64>,
        user_data: *mut c_void,
    ) -> Result<&'b FormatterToken<'b>> {
        unsafe {
            let mut token = mem::uninitialized();
            check!(
                ZydisFormatterTokenizeOperandEx(
                    self,
                    instruction,
                    index,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len(),
                    ip_to_runtime_addr(ip),
                    &mut token,
                    user_data,
                ),
                &*token
            )
        }
    }

    /// Sets a hook, allowing for customizations along the formatting
    /// process.
    ///
    /// This function returns the previously set hook.
    pub fn set_hook(&mut self, hook: Hook) -> Result<Hook> {
        unsafe {
            let mut cb = hook.to_raw();
            let hook_id = hook.to_id();

            check!(
                ZydisFormatterSetHook(self, hook_id as _, &mut cb),
                Hook::from_raw(hook_id, cb)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::ptr;

    #[test]
    fn test_prefixes() -> Result<()> {
        const CODE: &'static [u8] = &[0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76];

        let mut formatter = Formatter::new(FormatterStyle::Intel)?;
        formatter.set_property(FormatterProperty::HexPrefix(None))?;
        formatter.set_property(FormatterProperty::HexSuffix(Some("h")))?;

        let decoder = Decoder::new(MachineMode::Long64, AddressWidth::_64)?;

        let mut buffer = [0u8; 200];
        let mut buffer = OutputBuffer::new(&mut buffer[..]);

        for (instruction, _ip) in decoder.instruction_iterator(CODE, 0x0) {
            formatter.format_instruction(&instruction, &mut buffer, None, ptr::null_mut())?;
            assert_eq!(buffer.as_str().unwrap(), "call [rip+7648A5A0h]");
        }

        Ok(())
    }
}
