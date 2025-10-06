from transformers import pipeline

# multilingual sentiment model
_SENTIMENT_MODEL_ID = "cardiffnlp/twitter-xlm-roberta-base-sentiment"
_sentiment_pipe = pipeline("sentiment-analysis", model=_SENTIMENT_MODEL_ID)

def analyze_sentiment(text: str):
    """Return dict: {'label': 'positive', 'score': 0.98}"""
    result = _sentiment_pipe(text)[0]
    result['label'] = result['label'].lower()
    return result
