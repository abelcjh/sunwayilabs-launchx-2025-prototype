"""
Sentiment analysis module for analyzing user emotional state.
"""


class SentimentAnalyzer:
    """
    Analyzes the sentiment of user input to help tailor chatbot responses.
    """
    
    def __init__(self):
        """Initialize the sentiment analyzer."""
        # Keywords for basic sentiment detection
        self.positive_keywords = [
            'happy', 'good', 'great', 'wonderful', 'excellent', 'amazing',
            'fantastic', 'joy', 'love', 'blessed', 'grateful', 'thankful'
        ]
        self.negative_keywords = [
            'sad', 'depressed', 'anxious', 'worried', 'stressed', 'bad',
            'terrible', 'awful', 'horrible', 'hurt', 'pain', 'upset',
            'angry', 'frustrated', 'lonely', 'hopeless'
        ]
    
    def analyze(self, text):
        """
        Analyze the sentiment of the given text.
        
        Args:
            text (str): The text to analyze
            
        Returns:
            str: The sentiment classification ('positive', 'negative', or 'neutral')
        """
        if not text:
            return 'neutral'
        
        text_lower = text.lower()
        
        # Count positive and negative keywords
        positive_count = sum(1 for word in self.positive_keywords if word in text_lower)
        negative_count = sum(1 for word in self.negative_keywords if word in text_lower)
        
        # Determine sentiment
        if positive_count > negative_count:
            return 'positive'
        elif negative_count > positive_count:
            return 'negative'
        else:
            return 'neutral'
    
    def get_sentiment_score(self, text):
        """
        Get a numerical sentiment score.
        
        Args:
            text (str): The text to analyze
            
        Returns:
            float: A score between -1 (very negative) and 1 (very positive)
        """
        if not text:
            return 0.0
        
        text_lower = text.lower()
        positive_count = sum(1 for word in self.positive_keywords if word in text_lower)
        negative_count = sum(1 for word in self.negative_keywords if word in text_lower)
        
        total_keywords = positive_count + negative_count
        if total_keywords == 0:
            return 0.0
        
        return (positive_count - negative_count) / total_keywords
