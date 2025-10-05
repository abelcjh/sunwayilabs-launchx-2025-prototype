# Mental Health Chatbot

A compassionate mental health support chatbot built using Rogerian (person-centered) therapy principles.

## Overview

This chatbot provides a safe, supportive space for users to express their thoughts and feelings. It uses Rogerian therapy techniques including active listening, empathetic understanding, and unconditional positive regard.

**Important:** This chatbot is not a replacement for professional mental health care. If you're experiencing a crisis, please contact emergency services or a crisis hotline.

## Project Structure

```
mental-health-chatbot/
├─ app/
│  ├─ main.py                    # Main entry point
│  ├─ chatbot.py                 # Chatbot logic and Rogerian therapy implementation
│  ├─ sentiment.py               # Sentiment analysis module
│  ├─ prompts/
│  │   └─ rogerian_prompt.txt    # Rogerian therapy system prompt
├─ data/
│  └─ sample_conversations.json  # Sample conversation examples
├─ tests/
│  └─ test_placeholder.py        # Test suite
├─ .env.example                  # Environment variables template
├─ requirements.txt              # Python dependencies
├─ README.md                     # This file
└─ LICENSE                       # Apache 2.0 License
```

## Features

- **Rogerian Therapy Approach**: Uses person-centered therapy principles
- **Sentiment Analysis**: Analyzes user emotional state to tailor responses
- **Conversation History**: Maintains context throughout the conversation
- **Empathetic Responses**: Validates and reflects user feelings
- **Safe Environment**: Non-judgmental and supportive interactions

## Installation

1. Clone the repository:
```bash
git clone https://github.com/abelcjh/sunwayilabs-launchx-2025-prototype.git
cd sunwayilabs-launchx-2025-prototype
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. (Optional) Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys if integrating with LLM services
```

## Usage

Run the chatbot:
```bash
python app/main.py
```

The chatbot will start an interactive session where you can:
- Share your thoughts and feelings
- Receive empathetic, supportive responses
- Exit by typing 'quit' or 'exit'

## Development

### Running Tests

```bash
pytest tests/
```

### Adding Features

The codebase is modular and easy to extend:
- **`app/chatbot.py`**: Modify chatbot logic and response generation
- **`app/sentiment.py`**: Enhance sentiment analysis capabilities
- **`app/prompts/`**: Update or add new therapy approach prompts
- **`tests/`**: Add comprehensive test coverage

## Roadmap

- [ ] Integration with LLM APIs (OpenAI, Anthropic)
- [ ] Advanced sentiment analysis using transformers
- [ ] Web interface (Flask or Streamlit)
- [ ] Conversation persistence and analytics
- [ ] Multi-language support
- [ ] Crisis detection and resource recommendations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Disclaimer

This chatbot is for educational and supportive purposes only. It is not a substitute for professional mental health treatment. If you're experiencing a mental health crisis, please contact:

- **Emergency Services**: 911 (US) or your local emergency number
- **National Suicide Prevention Lifeline**: 988 (US)
- **Crisis Text Line**: Text HOME to 741741 (US)

## Acknowledgments

Built with care for the Sunway iLabs LaunchX 2025 program.
