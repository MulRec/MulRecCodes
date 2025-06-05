import os
import time
import re
import zlib
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import chardet
from sklearn.metrics import silhouette_score
import numpy as np
import json
import gzip
import multiprocessing
from typing import List, Dict, Any
from tqdm import tqdm
import lz4.block
from stages.multiprocess_doc2vec import infer_vectors_parallel

class CloneDetector:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.sim_threshold = float(config.sim_threshold)
        self.distance_threshold = float(config.distance_threshold)
    

    def detect_clones(self, project_dir: str, language: str):
        """Detect code clones in the project directory"""

        project_name = os.path.basename(project_dir)
        filep = os.path.join(self.config.results_root, language, project_name)
        filename = os.path.join(filep, "step1.json")
        if not os.path.exists(filename):
            os.makedirs(filep, exist_ok=True)

            start_time = time.time()
            self.logger.info(f"Starting clone detection in project {project_dir}")

            try:
                

           
                vuln_path = os.path.join(self.config.vuln_data_dir, language.lower(), "vul")
                # non_vuln_path = f"{self.config.vuln_dir}/{language.lower()}/no_vul"

             
                vuln_document = []
                vuln_filename = []
                self.logger.info(f"Scanning vulnerability files in {vuln_path}")
                for path, _, files in os.walk(vuln_path):
                    for file in files:
                        filePath = os.path.join(path, file)
                        docs = self.getfilelines(filePath)
                        if docs is not None:
                            vuln_filename.append(filePath)
                            vuln_document.append(docs)

            
                vector_cache_file = os.path.join(f"{self.config.base_dir}", f"data_{language}", f"vuln_vectors_{language}.npy")
                os.makedirs(f"{self.config.base_dir}/data_{language}", exist_ok=True)

                model_file = os.path.join(f"{self.config.base_dir}", f"data_{language}", "doc2vec_model")   

                if os.path.exists(vector_cache_file):
                    self.logger.info(f"Loading cached vulnerability vectors from {vector_cache_file}")
                    vuln_vectors = np.load(vector_cache_file)
                else:
                    self.logger.info("Computing vulnerability vectors...")
                    vuln_vectors = self.doc2vec(vuln_document, model_file)
                    np.save(vector_cache_file, vuln_vectors)
                    self.logger.info(f"Vulnerability vectors saved to {vector_cache_file}")

             
                function_document = []
                function_filename = []

                self.logger.info(f"Scanning project files in {project_dir}")
                for path, _, files in os.walk(project_dir):
                    for file in files:
                        filePath = os.path.join(path, file)
                        docs = self.getfilelines(filePath)
                        if docs is not None:
                            function_filename.append(filePath)
                            function_document.append(docs)

                self.logger.info(f"Number of target functions: {len(function_filename)}")
                if not function_document:
                    self.logger.warning("No functions found in the project directory")
                    return [], {'total_functions': 0, 'detected_clones': 0, 'execution_time': time.time() - start_time}

              

                cluster_start = time.time()
                cluster_stats = self.doc2vec_cluster(function_document, model_file)
                cluster_end = time.time()
                cluster_time = cluster_end - cluster_start
                self.logger.info(f"Clustering time: {cluster_time:.2f} seconds")
                self.logger.info(f"Number of clusters: {len(cluster_stats)}")


               
                cosine_start = time.time()
                similarity_scores, filtered_groups = self.parallel_similarity_calculation(
                    cluster_stats, vuln_vectors,  self.sim_threshold
                )
                cosine_end = time.time()
                cosine_time = cosine_end - cosine_start
                self.logger.info(f"Cosine similarity calculation time: {cosine_time:.2f} seconds")
                

            
                ncd_start = time.time()
                matching_dict = self.parallel_matching(
                    filtered_groups, cluster_stats, vuln_document, function_document,
                    vuln_filename, function_filename, self.distance_threshold
                )
                ncd_end = time.time()
                ncd_time = ncd_end - ncd_start
                self.logger.info(f"NCD calculation time: {ncd_time:.2f} seconds")

              
                self.logger.info("Recall or filter rate:")
                recall = len(matching_dict) / len(function_filename) if function_filename else 0
                self.logger.info(f"Recall rate: {recall:.4f}")

              
                # os.makedirs(self.config.results_root, exist_ok=True)

                if len(matching_dict) > 0:
                    with open(filename, 'w') as jsonfile:
                        json.dump(matching_dict, jsonfile, indent=4, ensure_ascii=False)
                    self.logger.info(f"Matching results saved to {filename}")

              
                suspicious_pairs = []
                for func_file, matched_vulns in matching_dict.items():
                    for vuln_file in matched_vulns:
                       
                        
                        pair = {
                            'source_function': func_file,
                            'vulnerable_template': vuln_file,
                        }
                        suspicious_pairs.append(pair)

                total_functions = len(function_filename)

                stats = {
                    'total_functions': total_functions,
                    'detected_clones': len(suspicious_pairs),
                    'cluster_time': cluster_time,
                    'cosine_time': cosine_time,
                    'ncd_time': ncd_time,
                    'recall_rate': recall,
                    'execution_time': time.time() - start_time
                }

                self.logger.info(f"Clone detection completed in {stats['execution_time']:.2f} seconds")
                self.logger.info(f"Detected {stats['detected_clones']} suspicious clone pairs")

                return matching_dict, stats

            except Exception as e:
                self.logger.error(f"Clone detection failed: {str(e)}", exc_info=True)
                return [], {'error': str(e), 'execution_time': time.time() - start_time}
        else:           
            self.logger.info(f"File {filename} already exists, skipping detecting")
            with open(filename, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data, {}


    def getfilelines(self, file_path):

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                code = file.read()
        except UnicodeDecodeError:
            with open(file_path, 'rb') as file:  # open as binary to detect encoding
                raw_data = file.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding']
            try:
                with open(file_path, 'r', encoding=encoding) as file:
                    code = file.read()
            except UnicodeDecodeError:
                return None
                pass
        return code
    




    def doc2vec_cluster(self, documents, model_path):
       
        def tokenize_code(code):
            tokens = re.findall(r'\w+|[^\w\s]', code, re.UNICODE)
            return tokens if tokens else ["<EMPTY>"]


      
        if os.path.exists(model_path):
            print(" loading Doc2Vec model...")
            model = Doc2Vec.load(model_path)
        else:
          
            print("trainning Doc2Vec model...")

            preprocessed_documents = [tokenize_code(doc) for doc in documents]

          
            tagged_data = [
                TaggedDocument(words=doc, tags=[str(i)])
                for i, doc in enumerate(preprocessed_documents)
                if doc 
            ]

            # print("Tagged Data:", tagged_data)

         
            model = Doc2Vec(
                vector_size=100,
                window=5,      
                min_count=1,  
                workers=4,     
                epochs=50       
            )

          
            model.build_vocab(tagged_data)
            # print(f"len of model vocab: {len(model.wv)}")
           

           
            model.train(tagged_data, total_examples=model.corpus_count, epochs=model.epochs)
            model.save(model_path)

       
      

        print("Generating Vectors...")
 

        vectors = infer_vectors_parallel(model, documents)

        # vectors = []
        # for doc in tqdm(documents):
        #     tokens = tokenize_code(doc)
        #     vector = model.infer_vector(tokens)
        #     vectors.append(vector)

        vectors = np.array(vectors)


       
        n = int(len(vectors) ** 0.5)
        # print("\n=== cluster result ===")
        # vectors = [model.dv[str(i)] for i in range(len(tagged_data))]
        kmeans = KMeans(n_clusters=n, random_state=42)
        labels = kmeans.fit_predict(vectors)



   
        cluster_stats = {}

      
        for cluster_id in range(n):
          
            mask = (labels == cluster_id)
            cluster_vectors = vectors[mask] 
            vector_ids = np.where(mask)[0] 

           
            centroid = kmeans.cluster_centers_[cluster_id]
            mean = cluster_vectors.mean(axis=0)
            q1 = np.percentile(cluster_vectors, 25, axis=0)
            min_val = cluster_vectors.min(axis=0)
            max_val = cluster_vectors.max(axis=0)

         
            cluster_stats[cluster_id] = {
                "centroid": centroid,
                "mean": mean,
                "q1": q1,
                "min": min_val,
                "max": max_val,
                "vectors": cluster_vectors,
                "vector_ids": vector_ids
            }


        return cluster_stats
    

    def doc2vec(self, documents, model_path):
      
        def tokenize_code(code):
            tokens = re.findall(r'\w+|[^\w\s]', code, re.UNICODE)
            return tokens if tokens else ["<EMPTY>"]


     
        if os.path.exists(model_path):
            print("loading Doc2Vec model...")
            model = Doc2Vec.load(model_path)
        else:
            
            print("trainning Doc2Vec model...")

            preprocessed_documents = [tokenize_code(doc) for doc in documents]

           
            tagged_data = [
                TaggedDocument(words=doc, tags=[str(i)])
                for i, doc in enumerate(preprocessed_documents)
                if doc 
            ]

            # print("Tagged Data:", tagged_data)

           
            model = Doc2Vec(
                vector_size=100, 
                window=5,       
                min_count=1,    
                workers=4,     
                epochs=50     
            )

          
            model.build_vocab(tagged_data)
            print(f"len of model vocab: {len(model.wv)}")


        
            model.train(tagged_data, total_examples=model.corpus_count, epochs=model.epochs)
            model.save(model_path)

  
        vectors = []
        for doc in tqdm(documents):
            tokens = tokenize_code(doc)
            vector = model.infer_vector(tokens)
            vectors.append(vector)

        vectors = np.array(vectors)

        return vectors
    
    def compute_similarity(self, cluster_id, stats, vuln_vectors):

        stats_vectors = [
            stats["centroid"],
            stats["mean"],
            stats["q1"],
            stats["min"],
            stats["max"]
        ]

  
        similarities = cosine_similarity(stats_vectors, vuln_vectors)


        max_similarity = similarities.max()

        return cluster_id, max_similarity


    def parallel_similarity_calculation(self, cluster_stats, vuln_vectors, sim_threshold):
        similarity_scores = {}


        with multiprocessing.Pool() as pool:
          
            results = pool.starmap(self.compute_similarity,
                                [(cluster_id, stats, vuln_vectors) for cluster_id, stats in cluster_stats.items()])

        
            for cluster_id, centroid_sim in results:
                similarity_scores[cluster_id] = centroid_sim

      
        filtered_groups = [cluster_id for cluster_id, sim in similarity_scores.items() if sim >= sim_threshold]

        return similarity_scores, filtered_groups
    
    @staticmethod
    def get_compressed_length(text):
        return len(lz4.block.compress(text.encode('utf-8')))


    def NCD_Distance(self, x1, x2, Cx1, Cx2):
        # Cx1 = len(gzip.compress(x1.encode()))
        # Cx2 = len(gzip.compress(x2.encode()))
        x1x2 = " ".join([x1, x2])
        # Cx1x2 = len(gzip.compress(x1x2.encode()))
        Cx1x2 = self.get_compressed_length(x1x2)
        ncd = (Cx1x2 - min(Cx1, Cx2)) / max(Cx1, Cx2)
        return ncd

    def compute_matching_files(self, item):
        file, vuln_document, function_document, vuln_filename, distance_threshold, cs_vuln_document, cs_function_document = item
        matching_files = []
        for j, vuln_doc in enumerate(vuln_document):
            # distance = self.NCD_Distance(vuln_doc, function_document[file])
            distance = self.NCD_Distance(vuln_doc, function_document[file], cs_vuln_document[j], cs_function_document[file])
            if distance <= distance_threshold:
                matching_files.append(vuln_filename[j])
        return file, matching_files


    def parallel_matching(self, filtered_groups, cluster_stats, vuln_document, function_document, vuln_filename,
                        function_filename, distance_threshold):
        matching_dict = {}
        filenums = 0

        # with multiprocessing.Pool(processes=64) as pool:   
        #     for id in filtered_groups:
        #         fileids = cluster_stats[id]["vector_ids"]
        #         filenums += len(fileids)
        #       
        #         results = pool.starmap(self.compute_matching_files,
        #                             [(file, vuln_document, function_document, vuln_filename, distance_threshold) for file
        #                                 in fileids])

        #   
        #         for file, matching_files in results:
        #             if matching_files != []:
        #                 matching_dict[function_filename[file]] = matching_files


        cs_vuln_documents = [self.get_compressed_length(x1) for x1 in vuln_document]
        cs_function_documents = [self.get_compressed_length(x1) for x1 in function_document]

        tasks = []
        for id in filtered_groups:
            fileids = cluster_stats[id]["vector_ids"]
            filenums += len(fileids)

            for file in fileids:
                task = (file, vuln_document, function_document, vuln_filename, distance_threshold, cs_vuln_documents, cs_function_documents)
                tasks.append(task)

       
        with multiprocessing.Pool() as pool:   
          
            results = list(tqdm(pool.imap_unordered(self.compute_matching_files, tasks, chunksize=10), total = len(tasks)))

    
        for file, matching_files in results:
            if matching_files != []:
                matching_dict[function_filename[file]] = matching_files

        self.logger.info(f"after cluster: {filenums}")
        return matching_dict