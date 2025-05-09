import logging

def setup_logger(name, log_file, level=logging.INFO):
    """
    Sets up a logger with the specified name, log file, and log level.
    Args:
        name (str): Name of the logger.
        log_file (str): File path for the log file.
        level: Logging level (e.g., logging.INFO, logging.DEBUG).
    Returns:
        logging.Logger: Configured logger instance.
    """
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

if __name__ == "__main__":
    # Example usage
    logger = setup_logger("example_logger", "example.log")
    logger.info("This is an info message.")
    logger.error("This is an error message.")
