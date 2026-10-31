"""Real local semantic embeddings, loaded from an explicitly provisioned cache."""
class LocalSemanticEmbeddingClient:
    def __init__(self, model_id="sentence-transformers/all-MiniLM-L6-v2", model=None):
        self.model_id = model_id
        if model is None:
            from sentence_transformers import SentenceTransformer
            model = SentenceTransformer(model_id, local_files_only=True, trust_remote_code=False, device="cpu")
        self.model = model
        self.dimensions = model.get_sentence_embedding_dimension()

    def embed_text(self, text):
        return self.embed_texts([text])[0]

    def embed_texts(self, texts):
        if any(not t.strip() for t in texts):
            raise ValueError("Cannot embed empty text")
        return self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False).tolist()
