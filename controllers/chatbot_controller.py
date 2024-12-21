from flask import Blueprint, request, jsonify
try:
    # Untuk versi terbaru
    from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
except ImportError:
    # Untuk versi lama
    from llama_index.legacy import VectorStoreIndex

# from gpt_index import SimpleDirectoryReader, GPTListIndex,readers, GPTSimpleVectorIndex, LLMPredictor, PromptHelper
from langchain import OpenAI
from types import FunctionType
from llama_index import SimpleDirectoryReader, load_index_from_storage
import sys
import time 

from llama_index.storage.storage_context import StorageContext
from llama_index.service_context import ServiceContext
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.llms.groq import Groq
from llama_index.indices.base import load_index_from_storage
import os

# Setup Blueprint
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Define the embedding and LLM models
embed_model = HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L12-v2")
llm = Groq(model="llama-3.2-90b-vision-preview", api_key=GROQ_API_KEY)

# Configure Service Context
service_context = ServiceContext.from_defaults(embed_model=embed_model, llm=llm)

# Define Storage Context
storage_context = StorageContext.from_defaults(persist_dir="D:\\storage_mini")

# Load Index
index = load_index_from_storage(storage_context, service_context=service_context)

# Query Engine
query_engine = index.as_query_engine(service_context=service_context)