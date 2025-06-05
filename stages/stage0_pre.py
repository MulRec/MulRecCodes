import os
import subprocess
import pandas as pd
import time
from typing import List, Dict, Any
import re
import json
import shutil

class FunctionExtractor:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.supported_languages = {
            'Go', 'Python3', 'Java', 'JavaScript', 'CPP14', 'Ruby', 'Php', 'CSharp'
        }
    
    def clone_projects_from_json(self, json_path: str) -> List[Dict[str, str]]:
        """Read project information from JSON and clone to local, 
            returning a list of projects with language information"""
        
        if not os.path.exists(json_path):
            self.logger.error(f"Input JSON does not exist: {json_path}")
            return []
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                projects = json.load(f)
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON: {e}")
            return []
        
        results = []
        for project in projects:
            url = project.get('url')
            if not url:
                self.logger.warning("Missing 'url' in project entry")
                continue
                
            branch = project.get('branch', 'master')
            language = project.get('language', '').strip()
            
            try:
                # Skip if language is not provided
                if not language:
                    self.logger.warning(f"Skipping project {url} due to missing language information")
                    continue
                
                # Skip if language is not supported
                if language not in self.supported_languages:
                    self.logger.warning(f"Skipping project {url} with unsupported language: {language}")
                    continue
                
                project_name = url.split('/')[-1].replace('.git', '')
                project_dir = os.path.join(self.config.projects_dir, project_name)
                
                # Build project information dictionary
                project_info = {
                    'name': project_name,
                    'url': url,
                    'path': project_dir,
                    'language': language
                }
                
                if not os.path.exists(project_dir) and not os.path.exists(os.path.join(self.config.processed_dir, project_name)):
                    os.makedirs(project_dir, exist_ok=True)
                    start_time = time.time()
                    self.logger.info(f"Cloning project {project_name} from {url}")
                    
                    subprocess.run(
                        ['git', 'clone', '-b', branch, url, project_dir],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    
                    elapsed = time.time() - start_time
                    self.logger.info(f"Project {project_name} cloning completed in {elapsed:.2f} seconds")
                else:
                    self.logger.info(f"Project {project_name} already exists, skipping cloning")
                
                # Yield project info for processing
                yield project_info
                
            except Exception as e:
                self.logger.error(f"Failed to process project {url}: {str(e)}")
                continue


    def extract_functions(self, project_dir: str, output_dir: str, language: str) -> int:
        """
        Extract functions from a project and save them to the output directory
        
        Args:
            project_dir: Path to the project directory
            output_dir: Path to the output directory
            language: Programming language of the project
            
        Returns:
            Number of functions extracted
        """
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            start_time = time.time()
            self.logger.info(f"Extracting {language} functions from {project_dir}")
            
            try:
                if language == "Go":
                    # from stage0preprocess_functions import preprocess_go
                    self.preprocess_go(project_dir, output_dir)
                elif language == "Python3":
                    # from stage0preprocess_functions import preprocess_python
                    self.preprocess_python(project_dir, output_dir)
                elif language == "Java":
                    # from stage0preprocess_functions import preprocess_java
                    self.preprocess_java(project_dir, output_dir)
                elif language == "JavaScript":
                    # from stage0preprocess_functions import preprocess_js
                    self.preprocess_js(project_dir, output_dir)
                elif language == "CPP14":
                    # from stage0preprocess_functions import preprocess
                    self.preprocess(project_dir, output_dir)
                elif language == "Ruby":
                    # from stage0preprocess_functions import preprocess_ruby
                    self.preprocess_ruby(project_dir, output_dir)
                elif language == "Php":
                    # from stage0preprocess_functions import preprocess_php
                    self.preprocess_php(project_dir, output_dir)
                elif language == "CSharp":
                    # from stage0preprocess_functions import preprocess_csharp
                    self.preprocess_csharp(project_dir, output_dir)
                else:
                    self.logger.error(f"Unsupported language: {language}")
                    return 0

                # Calculate the number of extracted functions
                func_count = sum(1 for _, _, files in os.walk(output_dir) for f in files if os.path.isfile(os.path.join(output_dir, f)))
                elapsed = time.time() - start_time
                self.logger.info(f"Extracted {func_count} functions from {project_dir} in {elapsed:.2f} seconds")
                if os.path.exists(project_dir):
                    shutil.rmtree(project_dir)
                self.logger.info(f"delete {project_dir}")
                return func_count
            except Exception as e:
                self.logger.error(f"Error extracting functions: {str(e)}")
                return 0
        else:           
            self.logger.info(f"Project {output_dir} already exists, skipping extracting")

            with os.scandir(output_dir) as entries:
                file_count = sum(1 for entry in entries if entry.is_file())
            return file_count


    def function_purification(self, code: str, skip_loc_threshold=False) -> str:
        # remove comments
        code = re.sub('\/\*[\w\W]*?\*\/', "", code)
        code = re.sub(r'//.*?\n', "\n", code)
        # remove non-ASCII
        code = re.sub(r"[^\x00-\x7F]+", "", code)
        # remove #
        code = re.sub(r"^#.*", "", code, flags=re.MULTILINE)
        # Counting ; as a way to see how many code lines, We do not consider very short functions
        if not skip_loc_threshold and code.count(";") <= 3:
            return ""
        # remove the empty line to compact the code
        purified_code_lines = list(filter(lambda c: len(c.strip()) != 0, code.split("\n")))
        # Counting the line which blank or contain only 1 char, We do not consider very short functions
        loc = 0
        for i in range(len(purified_code_lines)):
            purified_code_lines[i] = purified_code_lines[i].strip()
            loc += 1 if len(purified_code_lines[i]) > 1 else 0
        if not skip_loc_threshold and loc <= 5:
            return ""
        return "\n".join(purified_code_lines)


    def preprocess(self, project_dir, cache_dir):

        # project_name = os.path.split(project_dir.rstrip("/"))[-1]
        # cache_dir = os.path.join(os.curdir, "processed", project_name)
        # os.makedirs(cache_dir, exist_ok=True)

        self.logger.info("Preprocessing Target Function Dataset")
        self.logger.info(f"Extracting function from {project_dir} to {cache_dir}")

        cmd = (f'{self.config.path_to_ctags} -R --kinds-C++=f -u --fields=-fP+ne --language-force=c --language-force=c++'
                f' --output-format=json -f - "{project_dir}"')
        self.logger.debug(f"{cmd}")
        all_function_list_str = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
            errors="ignore")

        current_file = ""
        current_code = []
        all_function_list = all_function_list_str.split("\n")
        total_functions = len(all_function_list)  # All function including those < 3 lines
        for line in all_function_list:
            if line == "":
                continue
            try:
                info = json.loads(line)
            except BaseException as e:
                self.logger.error(f"Error {e} When Parsing Ctag info: ", line)
                continue
            if info["path"] != current_file:
                ext = os.path.splitext(info["path"])[1].lower()
                if ext not in [".c", ".cc", ".cxx", ".cpp", ".c++", "cp", ".h", ".hh", "hp", ".hpp", ".hxx", ".h++"]:
                    continue
                try:
                    with open(info["path"]) as f:
                        current_code = f.read().split("\n")
                    current_file = info["path"]
                except:
                    self.logger.warning(f"Fail to Parse Function in {info['path']}")
                    continue
            # Get Function Range
            start_line = info["line"] - 1
            if "end" not in info:
                continue
            end_line = info["end"]

            # Reconstruct function declaration since sometimes they are something missing
            try:
                if "typeref" in info:
                    func_type_parts = info["typeref"].split(":")
                    if len(func_type_parts) > 1:
                        if func_type_parts[0] == "typename":
                            func_type = ":".join(func_type_parts[1:])
                        else:
                            func_type = func_type_parts[0] + " " + ":".join(func_type_parts[1:])
                    else:
                        func_type = func_type_parts[0]
                    if func_type[-1] not in ["*", "&"]:
                        func_type += " "
                else:
                    func_type = ""
                func_decl_parts = current_code[start_line].split(info["name"], 1)
                if len(func_decl_parts) >= 2:
                    current_code[start_line] = f"{func_type}{info['name']}{func_decl_parts[1]}"
                # Or we'll give up Reconstructing Declaration
            except Exception as e:
                self.logger.warning("Function Declaration Parse Error: {}".format(e))
            func_body = "\n".join(current_code[start_line:end_line])
            # function_body purification
            func_body = self.function_purification(func_body)
            if func_body == "":
                continue
            # ConstructPath
            relative_path = os.path.relpath(info["path"], project_dir)
            function_file_name = info["name"] + "@@@" + "@#@".join(relative_path.split("/"))
            function_file_name = function_file_name.replace("/", "%2F")
            function_file_name = function_file_name.replace("%", "%25")

            target_file = os.path.join(cache_dir, function_file_name)
            self.logger.debug(f"writing function to {target_file}")
            with open(target_file, "w") as f:
                f.write(func_body)
        self.logger.info("Target Function Preprocessing Finished")

    def function_purification_go(self, code: str, skip_loc_threshold=False) -> str:
        
        code = re.sub(r'\/\*[\s\S]*?\*\/', "", code)
       
        code = re.sub(r'//.*?\n', "\n", code)
        
       
        code = re.sub(r"[^\x00-\x7F]+", "", code)
        
       
        code = re.sub(r"^#.*", "", code, flags=re.MULTILINE)
        
        if not skip_loc_threshold and code.count("\n") <= 3:
            return ""
        purified_code_lines = list(filter(lambda c: len(c.strip()) != 0, code.split("\n")))
        
        loc = 0
        for i in range(len(purified_code_lines)):
            purified_code_lines[i] = purified_code_lines[i].strip() 
            loc += 1 if len(purified_code_lines[i]) > 1 else 0 
        #print(code)
        if not skip_loc_threshold and loc <= 5:
            return ""
        return "\n".join(purified_code_lines) 


    def preprocess_go(self, project_dir, cache_dir):

        # project_name = os.path.split(project_dir.rstrip("/"))[-1]
        # cache_dir = os.path.join(os.curdir, "processed", project_name)
        # os.makedirs(cache_dir, exist_ok=True)

        self.logger.info("Preprocessing Target Function Dataset")
        self.logger.info(f"Extracting functions from {project_dir} to {cache_dir}")

        cmd = f'{self.config.path_to_gotags} -R "{project_dir}"  | grep -v "^!"'
        self.logger.debug(f"{cmd}")
        all_function_list_str = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
            errors="ignore")

        current_file = ""
        current_code = []
        all_function_list = all_function_list_str.split("\n")
        
        total_functions = len(all_function_list)  # All function including those < 3 lines
        
        for line in all_function_list:
            if line == "":
                continue
            #print(line)
            parts = line.split("\t") 
            if len(parts) < 5:
                self.logger.error(f"Invalid line format: {line}")
                continue
            try:
                line_number = int(parts[2].split(';')[0]) 
                info = {
                "name": parts[0],  
                "path": parts[1], 
                "line": line_number, 
                "access": parts[3] if len(parts) > 3 else None, 
                "details": parts[4:] 
            }
            except BaseException as e:
                self.logger.error(f"Error {e} When Parsing gotags info: ", line)
                continue
            #print(info)
            if info["path"] != current_file:
                ext = os.path.splitext(info["path"])[1].lower()
                if ext != ".go":
                    continue
                try:
                    with open(info["path"]) as f:
                        current_code = f.read().split("\n")
                    current_file = info["path"]
                except:
                    self.logger.warning(f"Fail to Parse Function in {info['path']}")
                    continue
            #print(current_code)         
            # Get Function Range
            start_line = info["line"] - 1
            
            try:
                with open(info["path"]) as f:
                    lines = f.readlines()
            except Exception as e:
                self.logger.error(f"Failed to read file {info['path']}: {e}")
                return 0
            inside_function=False
            line_count=0
            bracket_count=0
            for line in lines[start_line:]:
                if re.match(r'^\s*func\s+' + re.escape(info["name"]) + r'\s*\(', line):
                    inside_function = True
                    line_count = 1 
                    bracket_count = line.count('{') - line.count('}')  
                elif inside_function:
                    line_count += 1 
                    bracket_count += line.count('{') - line.count('}')  
                if bracket_count == 0:  
                    break
            if line_count==0:
                continue
            end_line = start_line + line_count 
            # Function body extraction
            func_body = "\n".join(current_code[start_line:end_line])
            func_body = self.function_purification_go(func_body)
            if func_body == "":
                continue
            # ConstructPath
            relative_path = os.path.relpath(info["path"], project_dir)
            function_file_name = info["name"] + "@@@" + "@#@".join(relative_path.split("/"))
            function_file_name = function_file_name.replace("/", "%2F").replace("%", "%25")

            target_file = os.path.join(cache_dir, function_file_name)
            self.logger.debug(f"writing function to {target_file}")
            if len(target_file) > 255:
                target_file = target_file[:255]
            with open(target_file, "w") as f:
                f.write(func_body)
        
        self.logger.info("Target Function Preprocessing Finished")

    def function_purification_python(self, code: str, skip_loc_threshold=False) -> str:

      
        code = re.sub(r"'''[\s\S]*?'''", "", code)
        code = re.sub(r'"""[\s\S]*?"""', "", code)
        
      
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        
    
        code = re.sub(r"[^\x00-\x7F]+", "", code)
        
    
        lines = [line.strip() for line in code.split('\n') if line.strip()]
        

        effective_lines = sum(1 for line in lines if len(line) > 1)
     
        if not skip_loc_threshold and effective_lines < 5:
            return ""
        
        return '\n'.join(lines)

    def preprocess_python(self, project_dir, cache_dir):

        # project_name = os.path.split(project_dir.rstrip("/"))[-1]
        # cache_dir = os.path.join(os.curdir, "processed", project_name)
        # os.makedirs(cache_dir, exist_ok=True)

        self.logger.info("Preprocessing Target Function Dataset")
        self.logger.info(f"Extracting function from {project_dir} to {cache_dir}")

        cmd = (f'{self.config.path_to_ctags} -R --kinds-Python=f -u --fields=-fP+ne --language-force=python --language-force=python'
                f' --output-format=json -f temp.txt "{project_dir}"')
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(errors="ignore")
        with open("temp.txt", "r") as temp_file:
            all_function_list_str = temp_file.read()
        os.remove("temp.txt")
        # all_function_list_str = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
        #     errors="ignore")

        current_file = ""
        current_code = []
        all_function_list = all_function_list_str.split("\n")
        total_functions = len(all_function_list)  # All function including those < 3 lines
        for line in all_function_list:
            if line == "":
                continue
            try:
                info = json.loads(line)
            except BaseException as e:
                self.logger.error(f"Error {e} When Parsing Ctag info: ", line)
                continue
            if info["path"] != current_file:
                ext = os.path.splitext(info["path"])[1].lower()
                if ext not in [".py"]:
                    continue
                try:
                    with open(info["path"]) as f:
                        current_code = f.read().split("\n")
                    current_file = info["path"]
                except:
                    self.logger.warning(f"Fail to Parse Function in {info['path']}")
                    continue
            # Get Function Range
            start_line = info["line"] - 1
            if "end" not in info:
                continue
            end_line = info["end"]

            # Reconstruct function declaration since sometimes they are something missing
            try:
                if "typeref" in info:
                    func_type_parts = info["typeref"].split(":")
                    if len(func_type_parts) > 1:
                        if func_type_parts[0] == "typename":
                            func_type = ":".join(func_type_parts[1:])
                        else:
                            func_type = func_type_parts[0] + " " + ":".join(func_type_parts[1:])
                    else:
                        func_type = func_type_parts[0]
                    if func_type[-1] not in ["*", "&"]:
                        func_type += " "
                else:
                    func_type = ""
                func_decl_parts = current_code[start_line].split(info["name"], 1)
                if len(func_decl_parts) >= 2:
                    current_code[start_line] = f"{func_type}{info['name']}{func_decl_parts[1]}"
                # Or we'll give up Reconstructing Declaration
            except Exception as e:
                self.logger.warning("Function Declaration Parse Error: {}".format(e))
            func_body = "\n".join(current_code[start_line:end_line])
            # function_body purification
            func_body = self.function_purification_python(func_body)
            if func_body == "":
                continue
            # ConstructPath
            relative_path = os.path.relpath(info["path"], project_dir)
            function_file_name = info["name"] + "@@@" + "@#@".join(relative_path.split("/"))
            function_file_name = function_file_name.replace("/", "%2F")
            function_file_name = function_file_name.replace("%", "%25")

            target_file = os.path.join(cache_dir, function_file_name)
            self.logger.debug(f"writing function to {target_file}")
            with open(target_file, "w") as f:
                f.write(func_body)
        self.logger.info("Target Function Preprocessing Finished")

    def preprocess_java(self, project_dir, cache_dir):

        # project_name = os.path.split(project_dir.rstrip("/"))[-1]
        # cache_dir = os.path.join(os.curdir, "processed", project_name)
        # os.makedirs(cache_dir, exist_ok=True)

        self.logger.info("Preprocessing Target Function Dataset")
        self.logger.info(f"Extracting function from {project_dir} to {cache_dir}")

        # java function extraction
        cmd = (f'{self.config.path_to_ctags} -R --kinds-Java=+f -u --fields=-fP+ne --language-force=java'
                f' --output-format=json -f - "{project_dir}"')

        self.logger.debug(f"{cmd}")
        all_function_list_str = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
            errors="ignore")

        current_file = ""
        current_code = []
        all_function_list = all_function_list_str.split("\n")
        total_functions = len(all_function_list)  # All function including those < 3 lines
        for line in all_function_list:
            if line == "":
                continue
            try:
                info = json.loads(line)
            except BaseException as e:
                self.logger.error(f"Error {e} When Parsing Ctag info: ", line)
                continue
            if info["path"] != current_file:
                ext = os.path.splitext(info["path"])[1].lower()
                # c++ file
                # if ext not in [".c", ".cc", ".cxx", ".cpp", ".c++", "cp", ".h", ".hh", "hp", ".hpp", ".hxx", ".h++"]:
                #     continue

                # java file
                if ext not in [".java"]:
                    continue

                try:
                    with open(info["path"]) as f:
                        current_code = f.read().split("\n")
                    current_file = info["path"]
                except:
                    self.logger.warning(f"Fail to Parse Function in {info['path']}")
                    continue
            # Get Function Range
            start_line = info["line"] - 1
            if "end" not in info:
                continue
            end_line = info["end"]

            # Reconstruct function declaration since sometimes they are something missing
            try:
                if "typeref" in info:
                    func_type_parts = info["typeref"].split(":")
                    if len(func_type_parts) > 1:
                        if func_type_parts[0] == "typename":
                            func_type = ":".join(func_type_parts[1:])
                        else:
                            func_type = func_type_parts[0] + " " + ":".join(func_type_parts[1:])
                    else:
                        func_type = func_type_parts[0]
                    if func_type[-1] not in ["*", "&"]:
                        func_type += " "
                else:
                    func_type = ""
                func_decl_parts = current_code[start_line].split(info["name"], 1)
                if len(func_decl_parts) >= 2:
                    current_code[start_line] = f"{func_type}{info['name']}{func_decl_parts[1]}"
                # Or we'll give up Reconstructing Declaration
            except Exception as e:
                self.logger.warning("Function Declaration Parse Error: {}".format(e))
            func_body = "\n".join(current_code[start_line:end_line])
            # function_body purification
            func_body = self.function_purification(func_body)
            if func_body == "":
                continue
            # ConstructPath
            relative_path = os.path.relpath(info["path"], project_dir)
            function_file_name = info["name"] + "@@@" + "@#@".join(relative_path.split("/"))
            function_file_name = function_file_name.replace("/", "%2F")
            function_file_name = function_file_name.replace("%", "%25")

            target_file = os.path.join(cache_dir, function_file_name)
            self.logger.debug(f"writing function to {target_file}")
            with open(target_file, "w") as f:
                f.write(func_body)
        self.logger.info("Target Function Preprocessing Finished")

    def get_function_body(self, current_code, start_line):
        open_brackets = 0
        open_parentheses = 0 
        in_function = False
        in_string = False
        in_comment = False
        end_line = start_line
        param_mode = True  
        function_start = None
        function_body = ""

        for i in range(start_line, len(current_code)):
            line = current_code[i].strip()
            if i == start_line:
                function_start = line.find("function")
                if function_start != -1:
                    line = line[function_start:]
            j = 0
            while j < len(line):
                char = line[j]
                function_body += char
            
                if not in_string and not in_comment and ((j < len(line) - 1 and line[j:j+2] == '//') or line[j] == '#'):
                    function_body += line[j+1:]
                    break
                
         
                if not in_string and j < len(line) - 1 and line[j:j+2] == '/*':
                    in_comment = True
                    function_body += line[j+1]
                    j += 2
                    continue
            
                if in_comment and j < len(line) - 1 and line[j:j+2] == '*/':
                    in_comment = False
                    function_body += line[j+1]
                    j += 2
                    continue

          
                if in_comment:
                    j += 1
                    continue

             
                if char in ('"', "'") and not in_comment:
                    if in_string:
                        if char == in_string:
                            in_string = False
                    else:
                        in_string = char
                    j += 1
                    continue

              
                if in_string:
                    j += 1
                    continue

            
                if param_mode:
                    if char == '(':
                        open_parentheses += 1
                    elif char == ')':
                        open_parentheses -= 1
                     
                        if open_parentheses == 0:
                            param_mode = False
                    j += 1
                    continue

               
                if not param_mode:
                    if char == '{':
                        if not in_function:
                            in_function = True  
                        open_brackets += 1
                    elif char == '}':
                        open_brackets -= 1

             
                if in_function and open_brackets == 0:
                    end_line = i
                    return function_body, end_line

                j += 1
            function_body += '\n'
        return function_body, end_line


    def preprocess_js(self, project_dir, cache_dir):

        # project_name = os.path.split(project_dir.rstrip("/"))[-1]
        # cache_dir = os.path.join(os.curdir, "processed", project_name)
        # os.makedirs(cache_dir, exist_ok=True)

        self.logger.info("Preprocessing Target Function Dataset")
        self.logger.info(f"Extracting function from {project_dir} to {cache_dir}")

        cmd = (f'{self.config.path_to_ctags} -R --kinds-JavaScript=f -u --fields=-fP+ne --language-force=JavaScript'
                f' --output-format=json -f - "{project_dir}"')
        self.logger.debug(f"{cmd}")
        all_function_list_str = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
            errors="ignore")

        current_file = ""
        current_code = []
        all_function_list = all_function_list_str.split("\n")
        total_functions = len(all_function_list)  # All function including those < 3 lines
        for line in all_function_list:
            if not line.strip(): 
                continue
            if line.startswith("ctags: Notice: "): # ctags warning
                continue
            try:
                info = json.loads(line)
            except BaseException as e:
                self.logger.error(f"Error {e} When Parsing Ctag info: ", line)
                continue
            if info["path"] != current_file:
                ext = os.path.splitext(info["path"])[1].lower()
                if ext not in [".js", ".cjs", ".mjs", ".jsx"]:
                    continue
                try:
                    with open(info["path"]) as f:
                        current_code = f.read().split("\n")
                    current_file = info["path"]
                except:
                    self.logger.warning(f"Fail to Parse Function in {info['path']}")
                    continue
            # Get Function Range
            start_line = info["line"] - 1
            # Find the end line of the function
            func_body, end_line = self.get_function_body(current_code, start_line)

            if end_line >= len(current_code):
                self.logger.warning(f"Function end not found in {info['path']}")
                continue
            # Reconstruct function declaration since sometimes they are something missing
            func_lines = func_body.split("\n")
            try:
                first_line = func_lines[0]
                func_bracket_pos = first_line.find("(")
                func_lines[0] = f"function {info['name']}{first_line[func_bracket_pos:]}"
                # Or we'll give up Reconstructing Declaration
            except Exception as e:
                self.logger.warning("Function Declaration Parse Error: {}".format(e))
            func_body = "\n".join(func_lines)
            # function_body purification
            func_body = self.function_purification(func_body)
            if func_body == "":
                continue
            # ConstructPath
            relative_path = os.path.relpath(info["path"], project_dir)
            function_file_name = info["name"] + "@@@" + "@#@".join(relative_path.split("/"))
            function_file_name = function_file_name.replace("/", "%2F")
            function_file_name = function_file_name.replace("%", "%25")

            target_file = os.path.join(cache_dir, function_file_name)
            self.logger.debug(f"writing function to {target_file}")
            with open(target_file, "w") as f:
                f.write(func_body)
        self.logger.info("Target Function Preprocessing Finished")


    def function_purification_ruby(self, code: str, skip_loc_threshold=False) -> str:
        # remove comments
        code = re.sub(r'#(?!{).*(?=\n)', "\n", code)
        code = re.sub(r'(?<=\n)\s*=begin[\S\s]*?(?<=\n)\s*=end\s*(?=\n)', "", code)

        # remove non-ASCII
        code = re.sub(r"[^\x00-\x7F]+", "", code)


        # remove empty line
        code = re.sub(r" +(?=\n)", "", code)
        code = re.sub(r"^\n+", "", code)
        code = re.sub(r"(?<!\S)\n", "", code)

        # Remove whitespaces and newline that are used to maintain a good code style
        code = re.sub(r"(?<=,) *\n *", "", code)
        code = re.sub(r"(?<=&&) *\n *", "", code)
        code = re.sub(r"(?<=\|\|) *\n *", "", code)
        code = re.sub(r"(?<=\() *\n *", "", code)
        code = re.sub(r"\n *(?=\))", "", code)

        # # Counting ; as a way to see how many code lines, We do not consider very short functions
        if not skip_loc_threshold and code.count("\n") <= 3:
            return ""

        return code

    def preprocess_ruby(self, project_dir, cache_dir):
        
        # project_name = os.path.split(project_dir.rstrip("/"))[-1]
        # cache_dir = os.path.join(os.curdir, "processed", project_name)
        # os.makedirs(cache_dir, exist_ok=True)
        
        self.logger.info("Preprocessing Target Function Dataset")
        self.logger.info(f"Extracting function from {project_dir} to {cache_dir}")

        cmd = (f'{self.config.path_to_ctags} -R --kinds-ruby=f -u --fields=-fP+ne --languages=ruby'
                f' --output-format=json -f - "{project_dir}"')
        # cmd = f"{self.path_to_ctags} -R --output-format=json -f {project_dir}"
        self.logger.debug(f"{cmd}")
        all_function_list_str = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
            errors="ignore")

        current_file = ""
        current_code = []
        all_function_list = all_function_list_str.split("\n")
        total_functions = len(all_function_list)  # All function including those < 3 lines
        for line in all_function_list:
            if line == "":
                continue
            try:
                info = json.loads(line)
            except BaseException as e:
                self.logger.error(f"Error {e} When Parsing Ctag info: ", line)
                continue
            if info["path"] != current_file:
                ext = os.path.splitext(info["path"])[1].lower()
                if ext not in [".rb", ".gemspec"]:
                    continue
                try:
                    with open(info["path"]) as f:
                        current_code = f.read().split("\n")
                    current_file = info["path"]
                except:
                    self.logger.warning(f"Fail to Parse Function in {info['path']}")
                    continue
            # Get Function Range
            start_line = info["line"] - 1
            if "end" not in info:
                continue
            end_line = info["end"]

            # Reconstruct function declaration since sometimes they are something missing
            try:
                if "typeref" in info:
                    func_type_parts = info["typeref"].split(":")
                    if len(func_type_parts) > 1:
                        if func_type_parts[0] == "typename":
                            func_type = ":".join(func_type_parts[1:])
                        else:
                            func_type = func_type_parts[0] + " " + ":".join(func_type_parts[1:])
                    else:
                        func_type = func_type_parts[0]
                    if func_type[-1] not in ["*", "&"]:
                        func_type += " "
                else:
                    func_type = ""
                func_decl_parts = current_code[start_line].split(info["name"], 1)
                if len(func_decl_parts) >= 2:
                    current_code[start_line] = f"{func_type}{info['name']}{func_decl_parts[1]}"
                # Or we'll give up Reconstructing Declaration
            except Exception as e:
                self.logger.warning("Function Declaration Parse Error: {}".format(e))
            func_body = "\n".join(current_code[start_line:end_line])
            # function_body purification
            func_body = self.function_purification_ruby(func_body)
            if func_body == "":
                continue
            # ConstructPath
            relative_path = os.path.relpath(info["path"], project_dir)
            function_file_name = info["name"] + "@@@" + "@#@".join(relative_path.split("/"))
            function_file_name = function_file_name.replace("/", "%2F")
            function_file_name = function_file_name.replace("%", "%25")

            target_file = os.path.join(cache_dir, function_file_name)
            self.logger.debug(f"writing function to {target_file}")
            with open(target_file, "w") as f:
                f.write(func_body)
        self.logger.info("Target Function Preprocessing Finished")

    def find_function_end(self, current_code, start_line):
        open_brackets = 0
        open_parentheses = 0  
        in_function = False
        in_string = False
        in_comment = False
        end_line = start_line
        param_mode = True 

        for i in range(start_line, len(current_code)):
            line = current_code[i].strip()

            j = 0
            while j < len(line):
                char = line[j]

                
                if not in_string and not in_comment and (line[j:j+2] == '//' or line[j] == '#'):
                    break 
                
              
                if not in_string and j < len(line) - 1 and line[j:j+2] == '/*':
                    in_comment = True
                    j += 2
                    continue
               
                if in_comment and j < len(line) - 1 and line[j:j+2] == '*/':
                    in_comment = False
                    j += 2
                    continue

               
                if in_comment:
                    j += 1
                    continue

               
                if char in ('"', "'") and not in_comment:
                    if in_string:
                        if char == in_string: 
                            in_string = False
                    else:
                        in_string = char 
                    j += 1
                    continue

               
                if in_string:
                    j += 1
                    continue

              
                if param_mode:
                    if char == '(':
                        open_parentheses += 1
                    elif char == ')':
                        open_parentheses -= 1
                       
                        if open_parentheses == 0:
                            param_mode = False
                    j += 1
                    continue

                
                if not param_mode:
                    if char == '{':
                        if not in_function:
                            in_function = True 
                        open_brackets += 1
                    elif char == '}':
                        open_brackets -= 1

           
                if in_function and open_brackets == 0:
                    end_line = i
                    return end_line

                j += 1

        return end_line


    def preprocess_php(self, project_dir, cache_dir):
        
        # project_name = os.path.split(project_dir.rstrip("/"))[-1]
        # cache_dir = os.path.join(os.curdir, "processed", project_name)
        # os.makedirs(cache_dir, exist_ok=True)

        self.logger.info("Preprocessing Target Function Dataset")
        self.logger.info(f"Extracting function from {project_dir} to {cache_dir}")

        cmd = (f'{self.config.path_to_ctags} -R --kinds-PHP=f -u --fields=-fP+ne --language-force=php'
                f' --output-format=json -f - "{project_dir}"')
        self.logger.debug(f"{cmd}")
        all_function_list_str = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
            errors="ignore")

        current_file = ""
        current_code = []
        all_function_list = all_function_list_str.split("\n")
        total_functions = len(all_function_list)  # All function including those < 3 lines
        for line in all_function_list:
            if line == "":
                continue
            try:
                info = json.loads(line)
            except BaseException as e:
                self.logger.error(f"Error {e} When Parsing Ctag info: ", line)
                continue
            if info["path"] != current_file:
                ext = os.path.splitext(info["path"])[1].lower()
                if ext not in [".php", ".php3", ".php4", ".php5", ".php7", ".phtml"]:
                    continue
                try:
                    with open(info["path"]) as f:
                        current_code = f.read().split("\n")
                    current_file = info["path"]
                except:
                    self.logger.warning(f"Fail to Parse Function in {info['path']}")
                    continue
            # Get Function Range
            start_line = info["line"] - 1
            # Find the end line of the function
            end_line = self.find_function_end(current_code, start_line)

            if end_line >= len(current_code):
                self.logger.warning(f"Function end not found in {info['path']}")
                continue
            # Reconstruct function declaration since sometimes they are something missing
            try:
                if "typeref" in info:
                    func_type_parts = info["typeref"].split(":")
                    if len(func_type_parts) > 1:
                        if func_type_parts[0] == "typename":
                            func_type = ":".join(func_type_parts[1:])
                        else:
                            func_type = func_type_parts[0] + " " + ":".join(func_type_parts[1:])
                    else:
                        func_type = func_type_parts[0]
                    if func_type[-1] not in ["*", "&"]:
                        func_type += " "
                else:
                    func_type = ""
                # func_decl_parts = current_code[start_line].split(info["name"], 1)
                # if len(func_decl_parts) >= 2:
                #     current_code[start_line] = f"{func_type}{info['name']}{func_decl_parts[1]}"
                # Or we'll give up Reconstructing Declaration
            except Exception as e:
                self.logger.warning("Function Declaration Parse Error: {}".format(e))
            func_body = "\n".join(current_code[start_line:end_line + 1])
            # function_body purification
            func_body = self.function_purification(func_body)
            if func_body == "":
                continue
            # ConstructPath
            relative_path = os.path.relpath(info["path"], project_dir)
            function_file_name = info["name"] + "@@@" + "@#@".join(relative_path.split("/"))
            function_file_name = function_file_name.replace("/", "%2F")
            function_file_name = function_file_name.replace("%", "%25")

            target_file = os.path.join(cache_dir, function_file_name)
            self.logger.debug(f"writing function to {target_file}")
            with open(target_file, "w") as f:
                f.write(func_body)
        self.logger.info("Target Function Preprocessing Finished")

    def preprocess_csharp(self, project_dir, cache_dir):

        # project_name = os.path.split(project_dir.rstrip("/"))[-1]
        # cache_dir = os.path.join(os.curdir, "processed", project_name)
        # os.makedirs(cache_dir, exist_ok=True)

        self.logger.info("Preprocessing Target Function Dataset")
        self.logger.info(f"Extracting function from {project_dir} to {cache_dir}")

        cmd = (f'{self.config.path_to_ctags} -R --kinds-C#=m -u --fields=-fP+ne --language-force=C#'
                f' --output-format=json -f - "{project_dir}"')
        self.logger.debug(f"{cmd}")
        all_function_list_str = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True).decode(
            errors="ignore")

        current_file = ""
        current_code = []
        all_function_list = all_function_list_str.split("\n")
        total_functions = len(all_function_list)  # All function including those < 3 lines
        for line in all_function_list:
            if line == "":
                continue
            try:
                info = json.loads(line)
            except BaseException as e:
                self.logger.error(f"Error {e} When Parsing Ctag info: ", line)
                continue
            if info["path"] != current_file:
                ext = os.path.splitext(info["path"])[1].lower()
                if ext not in [".cs"]:
                    continue
                try:
                    with open(info["path"]) as f:
                        current_code = f.read().split("\n")
                    current_file = info["path"]
                except:
                    self.logger.warning(f"Fail to Parse Function in {info['path']}")
                    continue
            # Get Function Range
            start_line = info["line"] - 1
            if "end" not in info:
                continue
            end_line = info["end"]

            # Reconstruct function declaration since sometimes they are something missing
            try:
                if "typeref" in info:
                    func_type_parts = info["typeref"].split(":")
                    if len(func_type_parts) > 1:
                        if func_type_parts[0] == "typename":
                            func_type = ":".join(func_type_parts[1:])
                        else:
                            func_type = func_type_parts[0] + " " + ":".join(func_type_parts[1:])
                    else:
                        func_type = func_type_parts[0]
                    if func_type[-1] not in ["*", "&"]:
                        func_type += " "
                else:
                    func_type = ""
                func_decl_parts = current_code[start_line].split(info["name"], 1)
                if len(func_decl_parts) >= 2:
                    try:
                        func_type = ''
                        for decl in filter(lambda a:a!='', func_decl_parts[0].split(' ')):
                            func_type += decl + ' '
                    except:
                        pass
                    current_code[start_line] = f"{func_type}{info['name']}{func_decl_parts[1]}"
                # Or we'll give up Reconstructing Declaration
            except Exception as e:
                self.logger.warning("Function Declaration Parse Error: {}".format(e))
            func_body = "\n".join(current_code[start_line:end_line])
            # function_body purification
            func_body = self.function_purification(func_body)
            if func_body == "":
                continue
            # ConstructPath
            relative_path = os.path.relpath(info["path"], project_dir)
            function_file_name = info["name"] + "@@@" + "@#@".join(relative_path.split("/"))
            function_file_name = function_file_name.replace("/", "%2F")
            function_file_name = function_file_name.replace("%", "%25")

            target_file = os.path.join(cache_dir, function_file_name)
            self.logger.debug(f"writing function to {target_file}")
            try:
                with open(target_file, "w") as f:
                    f.write(func_body)
            except Exception as e:
                self.logger.error(f"Write failed")
                self.logger.error(e)
        self.logger.info("Target Function Preprocessing Finished")
