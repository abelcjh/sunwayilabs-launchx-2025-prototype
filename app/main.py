"""
Main entry point for the mental health chatbot application.
"""

from chatbot import MentalHealthChatbot
from sentiment import SentimentAnalyzer


def main():
    """
    Initialize and run the mental health chatbot.
    """
    print("Mental Health Chatbot")
    print("=" * 50)
    print("Welcome! I'm here to listen and support you.")
    print("Type 'quit' or 'exit' to end the conversation.")
    print("=" * 50)
    
    chatbot = MentalHealthChatbot()
    sentiment_analyzer = SentimentAnalyzer()
    
    while True:
        user_input = input("\nYou: ").strip()
        
        if user_input.lower() in ['quit', 'exit']:
            print("\nThank you for talking with me. Take care!")
            break
        
        if not user_input:
            continue
        
        # Analyze sentiment
        sentiment = sentiment_analyzer.analyze(user_input)
        print(f"[Sentiment: {sentiment}]")
        
        # Get chatbot response
        response = chatbot.get_response(user_input, sentiment)
        print(f"\nBot: {response}")


if __name__ == "__main__":
    main()
