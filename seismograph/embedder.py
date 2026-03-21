from sentence_transformers import SentenceTransformer


class Embedder:
    """Converts text into a 384-dimensional embedding vector.

    Uses the all-MiniLM-L6-v2 model — a small, fast model that captures
    semantic meaning. Two texts about similar topics will produce similar
    vectors (close together in 384-dim space), while unrelated texts will
    produce distant vectors.
    """

    def __init__(self):
        self.model = SentenceTransformer("all-MiniLM-L6-v2")

    def embed(self, text: str) -> list[float]:
        """Return a 384-dimensional embedding for the input text."""
        return self.model.encode(text).tolist()
