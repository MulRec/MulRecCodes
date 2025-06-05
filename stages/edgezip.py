import os
import json
import csv
import math
import importlib
import sys
import multiprocessing
from multiprocessing import Pool
from collections import Counter
from antlr4 import CommonTokenStream, InputStream, TerminalNode
import graphviz
import xgboost as xgb
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
import time
from typing import List
from datetime import datetime
from functools import partial



with open('/home/dataset/mygrammars.json', 'r', encoding='utf-8') as file:
    grammars = json.load(file)
grammars_dict = {item['name']: item for item in grammars if 'name' in item}
ROOT_FOLDER = "/home/dataset/mygrammars-v4"


class Node:
    def __init__(self, node_type, value):
        self.node_type = node_type
        self.value = value
        self.children = []


class FunctionInfo:
    def __init__(self, path):
        self.path = path
        self.original_edges = []   
        self.important_edges = []  
        self.replaced_edges = []   

        self.len_original = 0
        self.len_important = 0
        self.len_replaced = 0

        self.compression_rate1 = 0.0  
        self.compression_rate2 = 0.0  

    def update_lengths(self):
        self.len_original = len(self.original_edges)
        self.len_important = len(self.important_edges)
        self.len_replaced = len(self.replaced_edges)

    def compute_compression_rates(self):
        self.update_lengths()
        if self.len_original > 0:
            self.compression_rate1 = self.len_important / self.len_original
        else:
            self.compression_rate1 = 0.0
        if self.len_important > 0:
            self.compression_rate2 = self.len_replaced / self.len_important
        else:
            self.compression_rate2 = 0.0


class ParserManager:
    def __init__(self, language):
        self.language = language
        self.lexer_class, self.parser_class, self.start, _ = self.get_parser()
    
    def get_parser(self):
        result = grammars_dict.get(self.language)
        if not result:
            raise ValueError(f"not found {self.language} parser")
        parser = result.get('parser', 'N/A')
        start = result.get('start', 'N/A')
        new_path = parser + "/gen/"
        parser_name = self.language
        lexer_class, parser_class, rule_names = self.load_lexer_parser(new_path, parser_name)
        return lexer_class, parser_class, start, {item[0].upper() + item[1:] + "Context": 0 for item in rule_names}
    
    def load_lexer_parser(self, subdir, parser_name):
        if parser_name == 'Ruby':
            lexer_module_name = "CorundumLexer"
            parser_module_name = "CorundumParser"
        else:
            lexer_module_name = parser_name + "Lexer"
            parser_module_name = parser_name + "Parser"
        if subdir not in sys.path:
            sys.path.append(subdir)
        lexer_module = importlib.import_module(lexer_module_name)
        parser_module = importlib.import_module(parser_module_name)
        lexer_class = getattr(lexer_module, lexer_module_name)
        parser_class = getattr(parser_module, parser_module_name)
        rule_names = getattr(parser_class, 'ruleNames')
        return lexer_class, parser_class, rule_names
    
    def get_parsetree(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        input_stream = InputStream(code)
        lexer = self.lexer_class(input_stream)
        stream = CommonTokenStream(lexer)
        parser = self.parser_class(stream)
        try:
            parse_method = getattr(parser, self.start)
            tree = parse_method()
            return tree
        except Exception as e:
            print(f"parser {file_path} filed: {e}")
            return None

    def get_token(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        input_stream = InputStream(code)
        lexer = self.lexer_class(input_stream)
        token_stream = CommonTokenStream(lexer)
        try:
            
            token_stream.fill()
            tokens = token_stream.tokens

            
            filtered_texts = [token.text for token in tokens if token.text != ' ' and token.channel == 0]

            return filtered_texts
        except Exception as e:
            print(f"parser {file_path} filed: {e}")
            return None


class TreeProcessor:
    @staticmethod
    def convert_antlr_tree(antlr_node):
        node_type = antlr_node.__class__.__name__
        value = '' if isinstance(antlr_node, TerminalNode) else node_type
        node = Node(node_type, value)
        if not isinstance(antlr_node, TerminalNode):
            for child in antlr_node.getChildren():
                child_node = TreeProcessor.convert_antlr_tree(child)
                node.children.append(child_node)
        return node

    @staticmethod
    def make_edge_list(root):
        edges = []
        for child in root.children:
            edge = f"{root.node_type}->{child.node_type}"
            edges.append(edge)
            edges.extend(TreeProcessor.make_edge_list(child))
        return edges


class FeatureManager:
    # IMPORTANT_EDGES_FILE = "2important_edges_20.json"
    # VOCABULARY_FILE = "2vocabulary_all.json"
    
    def __init__(self, parser_manager, language, IMPORTANT_EDGES_FILE, VOCABULARY_FILE):
        self.parser_manager = parser_manager
        self.language = language
        self.IMPORTANT_EDGES_FILE = IMPORTANT_EDGES_FILE
        self.VOCABULARY_FILE = VOCABULARY_FILE
        os.makedirs(f"data_{language}", exist_ok=True)

    def process_file_edges(self, file_path):
        tree = self.parser_manager.get_parsetree(file_path)
        if not tree:
            return []
        custom_tree = TreeProcessor.convert_antlr_tree(tree)
        return TreeProcessor.make_edge_list(custom_tree)
    
    def process_files_edges(self, folder):
        file_paths = []
        for root, _, files in os.walk(folder):
            for file in files:
                file_paths.append(os.path.join(root, file))
        with Pool() as pool:
            results = pool.map(self.process_file_edges, file_paths)
        return file_paths, results
    
    def get_edge_features(self, vuln_path, non_vuln_path, t1):
        _, vuln_edges = self.process_files_edges(vuln_path)
        _, non_vuln_edges = self.process_files_edges(non_vuln_path)
        vuln_docs = [' '.join(edges) for edges in vuln_edges]
        non_vuln_docs = [' '.join(edges) for edges in non_vuln_edges]
        documents = vuln_docs + non_vuln_docs
        labels = [1] * len(vuln_docs) + [0] * len(non_vuln_docs)
        vectorizer = CountVectorizer(token_pattern=r'\S+')
        X = vectorizer.fit_transform(documents)
        clf = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
        clf.fit(X, labels)
        booster = clf.get_booster()
        importance_dict = booster.get_score(importance_type='weight')
        inv_vocab = {v: k for k, v in vectorizer.vocabulary_.items()}
        sorted_features = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        top_n = int(len(sorted_features) * t1 / 100)
        important_edges = {inv_vocab[int(k[1:])] for k, _ in sorted_features[:top_n]}
        return important_edges
    
    def extract_ngram_for_edge_list(self, edge_list, n=2):
        counter = Counter()
        if len(edge_list) >= n:
            for i in range(len(edge_list) - n + 1):
                ngram = tuple(edge_list[i:i+n])
                counter[ngram] += 1
        return counter

    def extract_ngram_combinations(self, edge_seqs, n=2):
        with Pool() as pool:
            counters = pool.starmap(self.extract_ngram_for_edge_list, [(edges, n) for edges in edge_seqs])
        total = Counter()
        for cnt in counters:
            total += cnt
        return total

    def generate_vocabulary(self, important_edge_seqs, t2):
        bigram_counter = self.extract_ngram_combinations(important_edge_seqs, n=2)
        vocabulary_full = sorted(bigram_counter.items(), key=lambda x: x[1], reverse=True)
        threshold = int(len(vocabulary_full) * t2 / 100)  
        vocabulary = {
            " ".join(bigram): count
            for bigram, count in vocabulary_full[:threshold] 
        }
        return vocabulary

    def get_or_generate_features(self, vuln_path, non_vuln_path, t1, t2):
        if not os.path.exists(self.IMPORTANT_EDGES_FILE):
            print("Generating new important edge features...")
            important_edges = self.get_edge_features(vuln_path, non_vuln_path, t1)
            with open(self.IMPORTANT_EDGES_FILE, "w", encoding="utf-8") as f:
                json.dump(list(important_edges), f, indent=4, ensure_ascii=False)
        else:
            print("Loading existing important edge features...")
            with open(self.IMPORTANT_EDGES_FILE, "r", encoding="utf-8") as f:
                important_edges = json.load(f)
        if not os.path.exists(self.VOCABULARY_FILE):
            print("Generating new 2-gram vocabulary...")
            _, edge_seqs = self.process_files_edges(vuln_path)
            important_edge_seqs = [[edge for edge in edges if edge.lower() in important_edges] for edges in edge_seqs]
            vocabulary = self.generate_vocabulary(important_edge_seqs, t2)
            with open(self.VOCABULARY_FILE, "w", encoding="utf-8") as f:
                json.dump(vocabulary, f, indent=4, ensure_ascii=False)
        else:
            print("Loading existing vocabulary...")
            with open(self.VOCABULARY_FILE, "r", encoding="utf-8") as f:
                vocabulary = json.load(f)
        return set(important_edges), vocabulary

    @staticmethod
    def replace_for_edge_list(edge_list, vocab_set):
        new_seq = []
        i = 0
        while i < len(edge_list):
            if i < len(edge_list) - 1:
                bigram_str = edge_list[i] + " " + edge_list[i+1]
                if bigram_str in vocab_set:
                    new_seq.append(edge_list[i] + "_" + edge_list[i+1])
                    i += 2
                    continue
            new_seq.append(edge_list[i])
            i += 1
        return new_seq

# 新增：SimilarityCalculator 类
class SimilarityCalculator:
    @staticmethod
    def needleman_wunsch(seq1, seq2, match=1, mismatch=-1, gap=-1):

        m, n = len(seq1), len(seq2)
  
        score = np.zeros((m + 1, n + 1), dtype=int)
        for i in range(m + 1):
            score[i][0] = gap * i
        for j in range(n + 1):
            score[0][j] = gap * j
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                diag = score[i - 1][j - 1] + (match if seq1[i - 1] == seq2[j - 1] else mismatch)
                up = score[i - 1][j] + gap
                left = score[i][j - 1] + gap
                score[i][j] = max(diag, up, left)
        if max(m, n) == 0:
            return 0
        else:
            return score[m][n] / max(m, n)
        
    @staticmethod 
    def jaccard_similarity(list1: List[str], list2: List[str]) -> float:
        
        count1 = Counter(list1)
        count2 = Counter(list2)

        
        keys = set(count1.keys()) | set(count2.keys())

       
        intersection = sum(min(count1[k], count2[k]) for k in keys)
        union = sum(max(count1[k], count2[k]) for k in keys)

        if union == 0:
            return 0.0
        else:
            return intersection / union
        
    def compute_similarity(self, function_sequences, threshold, output_path_v1, output_path_v2,
                        parser_manager, feature_manager, vocabulary, importantedge):

        all_tasks = []
        test_info_map = {}
        vuln_info_map = {}
        vul_start = time.time()
        
        for test_func, sequences in function_sequences.items():
            test_info = sequences["test_info"]
            test_info_map[test_func] = test_info
            for vuln_info in sequences["vuln_infos"]:
                task = (test_func, test_info.replaced_edges, vuln_info.path, vuln_info.replaced_edges)
                all_tasks.append(task)
                vuln_info_map[vuln_info.path] = vuln_info 


        with Pool(processes=int(multiprocessing.cpu_count()*1.5)) as pool:
            similarity_scores = pool.starmap(SimilarityCalculator.needleman_wunsch, 
                                            [(t[1], t[3]) for t in all_tasks], chunksize=5)
        vul_end = time.time()
        vul_time = vul_end - vul_start

        pat_start = time.time()
    
        similarity_results = {}
        version_1_results = {}
        patch_check_tasks = []

        for (task, score) in zip(all_tasks, similarity_scores):
            test_func, _, vuln_path, _ = task
            similarity_results.setdefault(test_func, []).append([vuln_path, score])
            if score >= threshold:
                version_1_results.setdefault(test_func, []).append([vuln_path, score])
             
                patch_path = vuln_path.replace('vul/non_sample', 'no_vul').replace('vul/sample', 'no_vul').replace('OLD', 'NEW')
                patch_check_tasks.append((test_func, vuln_path, patch_path, score))

    
        FS = FunctionSequenceProcessor(parser_manager, feature_manager, vocabulary)
        check_patch_func = partial(self.patch_check_worker, test_info_map=test_info_map,
                                    FS=FS, parser_manager=parser_manager,
                                    importantedge=importantedge, self_obj=self)
        with Pool() as pool:
            patch_results = pool.map(check_patch_func, patch_check_tasks)

        pat_end = time.time()
        pat_time = pat_end - pat_start

    
        version_2_results = {}
        for result in patch_results:
            if result: 
                test_func, vuln_path, score = result
                version_2_results.setdefault(test_func, []).append([vuln_path, score])

       
        with open(output_path_v1, "w", encoding="utf-8") as f:
            json.dump(version_1_results, f, indent=4, ensure_ascii=False)
        with open(output_path_v2, "w", encoding="utf-8") as f:
            json.dump(version_2_results, f, indent=4, ensure_ascii=False)

        return similarity_results, version_1_results, version_2_results, vul_time, pat_time
    

    def patch_check_worker(self, task, test_info_map, FS, parser_manager, importantedge, self_obj):
        test_func, vuln_path, patch_path, sim_score = task
        test_seq = test_info_map[test_func]

        if not os.path.exists(patch_path):
            print(f"[WARN] Patch not found: {patch_path}")
            return None

        try:
            patch_info = FS.process_target_func(patch_path, importantedge)
            patch_sim = self_obj.needleman_wunsch(test_seq.replaced_edges, patch_info.replaced_edges)

            if sim_score > patch_sim:
                return test_func, vuln_path, sim_score
            if sim_score == patch_sim:
                t_tokens = parser_manager.get_token(test_func)
                v_tokens = parser_manager.get_token(vuln_path)
                p_tokens = parser_manager.get_token(patch_path)
                v_sim = self_obj.jaccard_similarity(t_tokens, v_tokens)
                p_sim = self_obj.jaccard_similarity(t_tokens, p_tokens)
                if v_sim > p_sim:
                    return test_func, vuln_path, sim_score
        except Exception as e:
            print(f"[ERROR] Processing patch failed: {patch_path}, Error: {e}")

        return None



    def filter_similarity(self, main_cluster_path, similarity_data, output_path, threshold=0.7):
       
        with open(main_cluster_path, 'r') as f:
            main_cluster = json.load(f)
                
       
        filtered_results = {}
        
       
        for file_path, similarities in similarity_data.items():
            if file_path in main_cluster:
                filtered_entries = []
                for idx, sim in enumerate(similarities):
                    if sim > threshold:
                        filtered_entries.append([main_cluster[file_path][idx], sim])
                
                if filtered_entries:
                    filtered_results[file_path] = filtered_entries
        
        print(len(filtered_results))
        # 保存结果
        with open(output_path, 'w') as f:
            json.dump(filtered_results, f, indent=4)



class FunctionSequenceProcessor:
    def __init__(self, parser_manager, feature_manager, vocabulary):
        self.parser_manager = parser_manager
        self.feature_manager = feature_manager
        self.vocabulary = vocabulary

    def process_target_func(self, file_path, important_edges):
        func_info = FunctionInfo(file_path)
        tree = self.parser_manager.get_parsetree(file_path)
        if not tree:
            return func_info
        custom_tree = TreeProcessor.convert_antlr_tree(tree)
        func_info.original_edges = TreeProcessor.make_edge_list(custom_tree)
        func_info.important_edges = [edge for edge in func_info.original_edges if edge.lower() in important_edges]
        func_info.replaced_edges = FeatureManager.replace_for_edge_list(func_info.important_edges, set(self.vocabulary.keys()))
        func_info.compute_compression_rates()
        return func_info
    
    # Add to avoid noise create by altlr4
    @staticmethod
    def init_worker():
       
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')  

    def process_function_sequences(self, data, important_edges):

        sequences = {}
        file_list = []
     
        for test_func, vuln_funcs in data.items():
            file_list.append(test_func)
            file_list.extend(vuln_funcs)

        with Pool(processes=int(multiprocessing.cpu_count() * 1.5), initializer=self.init_worker) as pool:
            func_infos = pool.starmap(
                self.process_target_func,
                [(file_path, important_edges) for file_path in file_list],
                chunksize=10
            )
        idx = 0
        for test_func, vuln_funcs in data.items():
            test_info = func_infos[idx]
            idx += 1
            vuln_infos = func_infos[idx: idx + len(vuln_funcs)]
            idx += len(vuln_funcs)
            sequences[test_func] = {
                "test_info": test_info,
                "vuln_infos": vuln_infos
            }
        return sequences

 
    def get_function_length(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            return len(code)
        except Exception as e:
            print(f"Error getting length for {file_path}: {e}")
            return 0

    @staticmethod
    def record_compression_rates(sequences, output_csv_path):
        rates = []
        with open(output_csv_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Test Function", "Path", "Original Length", "Important Length", "Replaced Length", "Compression Rate 1", "Compression Rate 2"])
            for test_func, info in sequences.items():
                test_info = info["test_info"]
                writer.writerow([
                    test_func,
                    test_info.path,
                    test_info.len_original,
                    test_info.len_important,
                    test_info.len_replaced,
                    test_info.compression_rate1,
                    test_info.compression_rate2
                ])
                rates.append((test_info.compression_rate1, test_info.compression_rate2))
        if rates:
            avg_cr1 = sum(x[0] for x in rates) / len(rates)
            avg_cr2 = sum(x[1] for x in rates) / len(rates)
        else:
            avg_cr1, avg_cr2 = 0, 0
        print("Average Compression Rate 1:", avg_cr1)
        print("Average Compression Rate 2:", avg_cr2)
        with open(output_csv_path, 'a+', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([avg_cr1, avg_cr2])


def main():
    language = "CPP"
    parser_manager = ParserManager(language)
    feature_manager = FeatureManager(parser_manager)
    vuln_path = "/home/dataset/cache/old_new_funcs/vul"
    non_vuln_path = "/home/dataset/cache/old_new_funcs/no_vul"
    important_edges, vocabulary = feature_manager.get_or_generate_features(vuln_path, non_vuln_path, 0.2, 0.5)
    
    json_path = "/home/dataset/z1result/allvul/1cluster_xen_75.json"
    if os.path.exists(json_path):
        print("start JSON files...")
        func_processor = FunctionSequenceProcessor(parser_manager, feature_manager, vocabulary)
        sequences = func_processor.process_function_sequences(json_path, important_edges)

        similarity_calculator = SimilarityCalculator()
        os.makedirs("/home/dataset/z2result/allvul/20all", exist_ok=True)
        sim_results = similarity_calculator.compute_similarity(sequences, 
                                                               output_path="/home/dataset/z2result/allvul/20all/xen_all.json")
        print("similarity ok")
        print(len(sim_results))

        # csv_output_path = "/home/dataset/z2result/allvul/20all/compression_rates_xen.csv"
        # func_processor.record_compression_rates(sequences, csv_output_path)
    else:
        print(f"JSON file {json_path} not exit")


from datetime import datetime

def batch_main(language):
    


    parser_manager = ParserManager(language)
    feature_manager = FeatureManager(parser_manager, language)
    
   
    vuln_path = f"/home/dataset/cache/old_new_funcs/{language.lower()}/vul"
    non_vuln_path = f"/home/dataset/cache/old_new_funcs/{language.lower()}/no_vul"
    important_edges, vocabulary = feature_manager.get_or_generate_features(vuln_path, non_vuln_path, 0.2, 1)

   
    input_base = f"/home/dataset/mulGT/{language}"
    output_base = f"/home/dataset/mulresult/20all/{language}"
    os.makedirs(output_base, exist_ok=True)

    log_path = os.path.join(output_base, "batch_log.txt")
    log_lines = []

  
    for project_name in os.listdir(input_base):
        project_path = os.path.join(input_base, project_name)
        if not os.path.isdir(project_path):
            continue

        output_dir = os.path.join(output_base, project_name)
        os.makedirs(output_dir, exist_ok=True)

        
        project_results = {}

        start_time = time.time()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        try:

            func_processor = FunctionSequenceProcessor(parser_manager, feature_manager, vocabulary)

           
            for func_name in os.listdir(project_path):
                func_path = os.path.join(project_path, func_name)
                if not os.path.isdir(func_path):
                    continue

               
                test_files = [f for f in os.listdir(func_path) if f.endswith('.txt')]
                if not test_files:
                    continue
                test_file = os.path.join(func_path, test_files[0])

                
                vuln_files = [f for f in os.listdir(func_path) if f.endswith('_OLD.vul')]
                if not vuln_files:
                    continue

              
                patch_files = {
                    f.replace('_OLD.vul', '_NEW.vul'): os.path.join(func_path, f.replace('_OLD.vul', '_NEW.vul'))
                    for f in vuln_files
                }

               
                test_info = func_processor.process_target_func(test_file, important_edges)

             
                vuln_infos = []
                for vuln_file in vuln_files:
                    vuln_file_path = os.path.join(func_path, vuln_file)
                    vuln_info = func_processor.process_target_func(vuln_file_path, important_edges)
                    vuln_infos.append(vuln_info)

              
                sequences = {
                    test_file: {
                        "test_info": test_info,
                        "vuln_infos": vuln_infos
                    }
                }

              
                similarity_calculator = SimilarityCalculator()
                _, filter_result = similarity_calculator.compute_similarity(
                    sequences, 0.7, 
                    os.path.join(output_dir, f"{func_name}_sim_all.json"),
                    os.path.join(output_dir, f"{func_name}_sim.json"),
                    parser_manager, feature_manager, vocabulary, important_edges
                )

                if filter_result:
                    project_results[func_name] = filter_result[test_file]

           
            project_result_path = os.path.join(output_dir, f"{project_name}_results.json")
            with open(project_result_path, 'w', encoding='utf-8') as f:
                json.dump(project_results, f, indent=4)

            elapsed = time.time() - start_time

            log_lines.append(
                f"[{timestamp}] project: {project_name}\n"
                f"    Output: {project_result_path}\n"
                f"    Number of Functions: {len(project_results)}\n"
                f"    Time Consumption: {elapsed:.2f}s\n"
            )
        except Exception as e:
            log_lines.append(
                f"[{timestamp}] Error processing project {project_name}: {str(e)}\n"
            )

    
    with open(log_path, 'w', encoding='utf-8') as f:
        f.writelines(line + '\n' for line in log_lines)




if __name__ == '__main__':
    # # main()
    # languages = ["Python3", "Java", "JavaScript", "Go", "Php"]
    # for language in languages:
    #     batch_main(language)
    batch_main(language = "Ruby") #\ "Python3""Java""Ruby""JavaScript""Go""Php""CPP14"     "CSharp"
