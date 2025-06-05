import logging

def setup_logger(log_file):
    """Configure logger"""
    logger = logging.getLogger('multilang_clone_detection')
    logger.setLevel(logging.INFO)
    
    # Ensure log file directory exists
    import os
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Log format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger