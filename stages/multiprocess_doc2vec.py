from multiprocessing import Pool, cpu_count
import re
from tqdm import tqdm
import gensim.models.doc2vec


global_model = None


def tokenize_code(code):
    tokens = re.findall(r'\w+|[^\w\s]', code, re.UNICODE)
    return tokens if tokens else ["<EMPTY>"]


def process_document(doc):

    tokens = tokenize_code(doc)
    
    return global_model.infer_vector(tokens)

def init_worker(model):
 
    global global_model
    global_model = model

def infer_vectors_parallel(model, documents, processes=32):

    processes = int(cpu_count() * 1.5)
    

    with Pool(
        processes=processes,
        initializer=init_worker,
        initargs=(model,)
    ) as pool:
    
        results = list(tqdm(
            pool.imap(process_document, documents),
            total=len(documents),
            desc="Inferred Document Vector",
            unit="doc"
        ))
    
    return results