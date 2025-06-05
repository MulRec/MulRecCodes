import os
import sys
import time
import csv
import json
from typing import List, Dict, Any
from tqdm import tqdm
from .edgezip import ParserManager, FeatureManager, FunctionSequenceProcessor, SimilarityCalculator



class ResultVerifier:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
    
    def verify_results(self, suspicious_pairs, project_name: str, language: str):
        """Verify if suspicious clone pairs are actual vulnerabilities"""
        start_time = time.time()
        self.logger.info(f"Starting verification of {len(suspicious_pairs)} suspicious clone pairs for project {project_name}")
        
        try:

            parser_manager = ParserManager(language)

            important_file = os.path.join(f"data_{language}", f"2important_edges_{self.config.importance}.json")
            vocabulary_file = os.path.join(f"data_{language}", f"2vocabulary_{self.config.frequency}.json")
            feature_manager = FeatureManager(parser_manager, language, important_file, vocabulary_file)
            
 
            vuln_path = os.path.join(self.config.vuln_data_dir, language.lower(), "vul")
            non_vuln_path = os.path.join(self.config.vuln_data_dir, language.lower(), "no_vul")
            
   
            self.logger.info(f"Generating features from {vuln_path} and {non_vuln_path}")
            important_edges, vocabulary = feature_manager.get_or_generate_features(
                vuln_path, non_vuln_path, 
                float(self.config.importance), 
                int(self.config.frequency)
            )
            
    
            output_dir = os.path.join(self.config.results_root, language, project_name)
            os.makedirs(output_dir, exist_ok=True)
            
            log_path = os.path.join(output_dir, "2verification_log.txt")
            log_lines = []
            
       
            func_processor = FunctionSequenceProcessor(parser_manager, feature_manager, vocabulary)
            
            
   
            self.logger.info("Processing suspicious clone pairs...")

                
            try:
          
                sequences = func_processor.process_function_sequences(suspicious_pairs, important_edges)
                
                asttime = time.time() - start_time

                self.logger.info(f"AST generation  time: {asttime:.2f} seconds")


            
                similarity_calculator = SimilarityCalculator()
                similarity_results, version_1_results, version_2_results, vul_time, pat_time = similarity_calculator.compute_similarity(
                    sequences, 
                    float(self.config.similarity_threshold),
                    output_dir +"/step2.json", 
                    output_dir +"/step3.json",  
                    parser_manager, feature_manager, vocabulary, important_edges
                )
                

            except Exception as e:
                self.logger.warning(f"Failed to process : {str(e)}")
                log_lines.append(f"Error processing: {str(e)}\n")
            

       
            with open(log_path, 'w', encoding='utf-8') as f:
                f.writelines(log_lines)
            
            self.logger.info(f"Verification completed in {time.time()-start_time:.2f} seconds")
            self.logger.info(f"Vul completed in {vul_time:.2f} seconds")
            self.logger.info(f"Confirmed {len(version_1_results)} vulnerabilities in project {project_name}")
            self.logger.info(f"Patch completed in {pat_time:.2f} seconds")
            self.logger.info(f"Confirmed {len(version_2_results)} vulnerabilities in project {project_name}")
            
            return version_1_results, version_2_results
            
        except Exception as e:
            self.logger.error(f"Result verification failed: {str(e)}", exc_info=True)
            return [], []
    
    def save_results(self, results: List[Dict], project_name: str) -> None:
        """Save verification results to file"""
        try:
            if not results:
                self.logger.info(f"No vulnerabilities found in project {project_name}, result file not generated")
                return
                
            result_dir = os.path.join(self.config.result_dir, project_name)
            os.makedirs(result_dir, exist_ok=True)
            
           
            csv_file = os.path.join(result_dir, f"{project_name}_vulns.csv")
            with open(csv_file, 'w', newline='') as f:
                fieldnames = ['language', 'test_file', 'vuln_file', 'similarity_score', 'project']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
                
            self.logger.info(f"Results saved to {csv_file}")
                
          
            json_file = os.path.join(result_dir, f"{project_name}_vulns.json")
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=4)
                
            self.logger.info(f"Results saved to {json_file}")
                
        except Exception as e:
            self.logger.error(f"Failed to save results: {str(e)}")
            
    def save_summary_results(self, project_stats: List[Dict]) -> None:
        """Save summary statistics for multiple projects"""
        try:
            if not project_stats:
                self.logger.info("No project statistics to save")
                return
                
            summary_file = os.path.join(self.config.results_root, "summary_stats.csv")
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Check if file exists, create and write header if not
            file_exists = os.path.exists(summary_file)
            with open(summary_file, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(["Timestamp", "Project", "Language", "SuspiciousPairs", "Vulns", "VerifiedVulns", "ExecutionTime"])
                
                for stats in project_stats:
                    writer.writerow([
                        timestamp,
                        stats.get('project', 'unknown'),
                        stats.get('language', 'unknown'),
                        stats.get('suspicious_pairs', 0),
                        stats.get('vuln_pairs', 0),
                        stats.get('verified_vulns', 0),
                        f"{stats.get('execution_time', 0):.2f}"
                    ])
                    
            self.logger.info(f"Summary statistics saved to {summary_file}")
                
        except Exception as e:
            self.logger.error(f"Failed to save summary statistics: {str(e)}")

