use flexi_logger::{
    colored_default_format, detailed_format, Duplicate, FileSpec, Logger, WriteMode,
};
use log::*;
pub fn init_logger(origin: &str, depth: &str, save_log: bool) {
    let mut logger = Logger::try_with_str(depth)
        .unwrap()
        .format_for_stdout(colored_default_format);
    if save_log {
        logger = logger
            .log_to_file(
                FileSpec::default()
                    .directory(format!("../logs/{origin}"))
                    .basename(origin),
            )
            .format_for_files(detailed_format)
            .write_mode(WriteMode::Direct);
    }
    logger.duplicate_to_stdout(Duplicate::All).start().unwrap();

    info!("Logger initialized");
}
