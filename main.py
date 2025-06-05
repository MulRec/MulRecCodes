import os
import time
from utils.config import Config
from utils.logger import setup_logger
from stages.stage0_pre import FunctionExtractor
from stages.stage1_embed import CloneDetector
from stages.stage2_verify import ResultVerifier
import shutil


def main():
    # Load configuration
    config = Config('config.ini')
    logger = setup_logger(config.log_file)
    
    # Record start time
    start_time = time.time()
    logger.info("===== Multi-language Clone Vulnerability Detection Tool =====")
    
    # Initialize processing stages
    extractor = FunctionExtractor(config, logger)
    detector = CloneDetector(config, logger)
    verifier = ResultVerifier(config, logger)
    
    # Statistics
    project_stats = []
    
    # Process projects one by one
    logger.info("===== Starting project processing =====")
    
    
    for project_info in extractor.clone_projects_from_json(config.input_json):
        # processed_projects += 1
        project_start_time = time.time()
        project_dir = project_info['path']
        project_name = project_info['name']
        language = project_info['language']
        
        logger.info(f"===== Processing project {project_name} ({language}) =====")
        
        # Function extraction
        logger.info("--- Starting function extraction ---")
        output_dir = os.path.join(config.processed_dir, project_name)
        func_count = extractor.extract_functions(project_dir, output_dir, language)
        # total_functions += func_count
        logger.info(f"Extracted {func_count} functions from project {project_name}")
        
        # Clone detection
        suspicious_pairs = []
        clone_count = 0
        if func_count > 0:
            logger.info("--- Starting clone detection ---")
            suspicious_pairs, stats = detector.detect_clones(output_dir, language)
            clone_count = len(suspicious_pairs)
            # total_clones += clone_count
            logger.info(f"Detected {clone_count} suspicious clone pairs in project {project_name}")
            
            # Result verification
            verified_vulns = []
            vulns = []
            vuln_count = 0
            if clone_count > 0:
                logger.info("--- Starting result verification ---")
                vulns, verified_vulns = verifier.verify_results(suspicious_pairs, project_name, language)
                vuln_count = len(verified_vulns)
                # total_vulns += vuln_count
                logger.info(f"Confirmed {vuln_count} vulnerabilities in project {project_name}")
                
                # Save project-specific results
                if vuln_count > 0:
                    # project_results = [{
                    #     'project': project_name,
                    #     'language': language,
                    #     **vuln
                    # } for vuln in verified_vulns]
                    # verifier.save_results(project_results, prefix=project_name)
                    pass
                elif vuln_count == 0:
                    # if os.path.exists(output_dir):
                    #     shutil.rmtree(output_dir)
                    #     logger.info(f"delete {output_dir}")
                    pass
            else:
                # if os.path.exists(output_dir):
                #     shutil.rmtree(output_dir)
                #     logger.info(f"delete {output_dir}")
                pass
        else:
            vuln_count = 0
        
        
        project_execution_time = time.time() - project_start_time
        
        
        project_stats.append({
            'project': project_name,
            'language': language,
            'suspicious_pairs': clone_count,
            'vuln_pairs': len(vulns),
            'verified_vulns': vuln_count,
            'execution_time': project_execution_time
        })
    
    # Output overall statistics
    total_time = time.time() - start_time
    logger.info("===== Detection process completed =====")
    logger.info(f"Total projects processed: {len(project_stats)}")
    logger.info(f"Total functions extracted: {sum(p.get('suspicious_pairs', 0) for p in project_stats)}")
    logger.info(f"Total suspicious clone pairs detected: {sum(p.get('suspicious_pairs', 0) for p in project_stats)}")
    logger.info(f"Total confirmed vulnerabilities: {sum(p.get('verified_vulns', 0) for p in project_stats)}")
    logger.info(f"Total time elapsed: {total_time:.2f} seconds")
    logger.info("=====================================")
    
    # Save final summary results
    if project_stats:
        verifier.save_summary_results(project_stats)

if __name__ == "__main__":
    main()