import streamlit as st
from chatbot import rogerian_reply
from sentiment import analyze_sentiment

st.set_page_config(page_title="EVE – AI Mental Health Companion", page_icon="🧠")

st.title("🧠 EVE: AI Mental Health Companion")
st.caption("Empathetic, reflective support — English & Bahasa Malaysia")

st.warning("⚠️ EVE is not a medical service. If you are in danger or considering self-harm, contact emergency services or a trusted hotline immediately.")

if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat
for m in st.session_state.messages:
    if m["role"] == "user":
        st.markdown(f"**You:** {m['content']}")
    else:
        st.markdown(f"**EVE:** {m['content']}")

user_input = st.text_area("💭 How are you feeling today? / Bagaimana perasaan anda hari ini?", height=120)

col1, col2 = st.columns(2)
if col1.button("Talk to EVE"):
    if user_input.strip():
        st.session_state.messages.append({"role": "user", "content": user_input})
        sentiment = analyze_sentiment(user_input)
        with st.expander("Sentiment Detected"):
            st.write(f"**{sentiment['label'].title()}** (score: {sentiment['score']:.2f})")
        response = rogerian_reply(user_input)
        st.session_state.messages.append({"role": "assistant", "content": response['reply']})
        st.experimental_rerun()
    else:
        st.info("Please enter a message first.")

if col2.button("Clear Chat"):
    st.session_state.messages = []
    st.experimental_rerun()
