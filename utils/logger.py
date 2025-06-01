import logging
import os
from logging.handlers import RotatingFileHandler

# Create logs directory if it doesn't exist
log_directory = "logs"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Create formatters
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

def setup_logger(name, log_file, level=logging.INFO):
    """Function to setup a logger with specific configuration"""
    handler = RotatingFileHandler(
        os.path.join(log_directory, log_file), 
        maxBytes=10000000,  # 10MB
        backupCount=5
    )
    handler.setFormatter(log_formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

# Setup different loggers for different purposes
info_logger = setup_logger('info_logger', 'info.log', logging.INFO)
error_logger = setup_logger('error_logger', 'error.log', logging.ERROR)
auth_logger = setup_logger('auth_logger', 'auth.log', logging.INFO)
db_logger = setup_logger('db_logger', 'database.log', logging.INFO)

# Console handler for development
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)

# Add console handler to all loggers
for logger in [info_logger, error_logger, auth_logger, db_logger]:
    logger.addHandler(console_handler)
