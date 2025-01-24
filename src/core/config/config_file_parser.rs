use crate::core::config::config_manager::ConfigManager;
use std::io::{self, Read, Seek, SeekFrom};

use crate::get_command;

use super::config_context::ConfigContext;

pub fn parse_context_of(ctx: &mut ConfigContext) -> io::Result<()> {
    while let Ok(status) = get_token_of(ctx) {
        match status {
            ParseStutus::BlockEnd => return Ok(()),
            ParseStutus::Finish => return Ok(()),
            _ => {
                handler_command_of(ctx);
            }
        }
    }

    Ok(())
}

pub fn get_token_of(ctx: &mut ConfigContext) -> io::Result<ParseStutus> {
    ctx.current_cmd_args.clear();
    let mut in_word = false;
    let mut is_first = true;

    while let Ok(c) = get_u8_of(ctx) {
        match c {
            c if c.is_ascii_whitespace() => {
                if in_word {
                    in_word = false;
                }
            }
            b'{' => return Ok(ParseStutus::BlockStart),
            b'}' => return Ok(ParseStutus::BlockEnd),
            b';' => return Ok(ParseStutus::Normal),
            b'#' => {
                while let Ok(ch) = get_u8_of(ctx) {
                    if ch == b'\n' {
                        break;
                    }
                }
            }
            _ => {
                if is_first {
                    if ctx.current_cmd_args.is_empty() {
                        ctx.current_cmd_args.push(String::new());
                    }
                    ctx.current_cmd_args[0].push(c as char);
                    is_first = false;
                    in_word = true;
                } else {
                    if !in_word {
                        ctx.current_cmd_args.push(String::new());
                    }
                    let args_index = ctx.current_cmd_args.len() - 1;
                    ctx.current_cmd_args[args_index].push(c as char);
                    in_word = true;
                }
            }
        }
    }

    Ok(ParseStutus::Finish)
}

pub fn get_u8_of(ctx: &mut ConfigContext) -> io::Result<u8> {
    ctx.reader.seek(SeekFrom::Start(ctx.parse_pos))?;
    let mut buf = [0; 1];
    ctx.reader.read_exact(&mut buf)?;
    ctx.parse_pos += 1;
    Ok(buf[0])
}

pub fn handler_command_of(ctx: &mut ConfigContext) {
    let cmd_name = {
        if ctx.current_cmd_args.is_empty() {
            return;
        }
        &ctx.current_cmd_args[0]
    };
    println!("處理指令: {cmd_name}");

    if let Some(cmd) = get_command!(&cmd_name) {
        if let Some(type_id) = ctx.current_block_type_id {
            if !cmd.cmd_valid_block.contains(&type_id) && !cmd.cmd_valid_block.is_empty() {
                panic!("Command in wrong block");
            }
        }

        (cmd.cmd_set)(ctx);
    }
}

pub enum ParseStutus {
    Normal,
    BlockStart,
    BlockEnd,
    Finish,
}
