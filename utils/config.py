import configparser
import os

class Config:
    def __init__(self, config_file):
        self.config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        self.config.read(config_file)
        
        # Path configurations
        self.base_dir = self.config.get('PATHS', 'base_dir')
        self.projects_dir = self.config.get('PATHS', 'projects_dir')
        self.processed_dir = self.config.get('PATHS', 'processed_dir')
        self.vuln_data_dir = self.config.get('PATHS', 'vuln_data_dir') 
        self.cache_dir = self.config.get('PATHS', 'cache_dir')
        self.results_root = self.config.get('PATHS', 'results_root') 
        self.log_dir = self.config.get('PATHS', 'log_dir')
        self.log_file = self.config.get('PATHS', 'log_file')
        self.input_json = self.config.get('PATHS', 'input_json') 
        
        
        # Tool configurations
        self.path_to_ctags = self.config.get('TOOLS', 'path_to_ctags')
        self.path_to_gotags = self.config.get('TOOLS', 'path_to_gotags')
        
        # Parameter configurations
        self.sim_threshold = float(self.config.get('PARAMS', 'sim_threshold'))  
        self.distance_threshold = float(self.config.get('PARAMS', 'distance_threshold'))  
        self.importance = int(self.config.get('PARAMS', 'importance')) 
        self.frequency = int(self.config.get('PARAMS', 'frequency'))
        self.similarity_threshold = float(self.config.get('PARAMS', 'similarity_threshold'))  
        
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)