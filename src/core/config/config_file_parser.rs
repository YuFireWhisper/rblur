use crate::core::config::config_manager::ConfigManager;
use std::{
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
    sync::{Mutex, OnceLock},
};

use crate::get_command;

use super::config_context::ConfigContext;

static CONFIG_FILE_PARSER: OnceLock<Mutex<ConfigFileParser>> = OnceLock::new();

pub struct ConfigFileParser {
    reader: BufReader<File>,
    index: u64,
}

impl ConfigFileParser {
    pub fn init(path: &str) -> io::Result<()> {
        let _ = CONFIG_FILE_PARSER.set(Mutex::new(ConfigFileParser {
            reader: BufReader::new(File::open(path)?),
            index: 0,
        }));
        Ok(())
    }

    pub fn instance() -> &'static Mutex<ConfigFileParser> {
        CONFIG_FILE_PARSER
            .get()
            .expect("ConfigFileParser is not initialized")
    }

    pub fn parse(&mut self, ctx: &mut ConfigContext) -> io::Result<()> {
        loop {
            while let Ok(status) = self.get_token(ctx) {
                match status {
                    ParseStutus::BlockEnd => return Ok(()),
                    _ => {
                        self.config_handler(ctx);
                    }
                }
            }
        }
    }

    pub fn get_token(&mut self, ctx: &mut ConfigContext) -> io::Result<ParseStutus> {
        let mut in_word = false;
        let mut is_first = true;

        while let Ok(c) = self.get_u8() {
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
                    while let Ok(ch) = self.get_u8() {
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

    pub fn get_u8(&mut self) -> io::Result<u8> {
        self.reader.seek(SeekFrom::Start(self.index))?;
        let mut buf = [0; 1];
        self.reader.read_exact(&mut buf)?;
        self.index += 1;
        Ok(buf[0])
    }

    pub fn config_handler(&mut self, ctx: &mut ConfigContext) {
        let cmd_name = {
            if ctx.current_cmd_args.is_empty() {
                return;
            }
            &ctx.current_cmd_args[0]
        };

        if let Some(cmd) = get_command!(&cmd_name) {
            if let Some(type_id) = ctx.current_block_type_id {
                if !cmd.cmd_valid_block.contains(&type_id) && !cmd.cmd_valid_block.is_empty() {
                    panic!("Command in wrong block");
                }
            }

            (cmd.cmd_set)(ctx);
        }
    }
}

pub enum ParseStutus {
    Normal,
    BlockStart,
    BlockEnd,
    Finish,
}
