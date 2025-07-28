import streamlit as st
from PIL import Image
from steganography import embed, extract

st.set_page_config(page_title="Image Steganography", layout="centered")

st.title("🔐 Image Steganography Tool (Streamlit Edition)")

operation = st.radio("Select Operation", ["Encode", "Decode"])

uploaded_image = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"])
bits = st.selectbox("Bits per channel", [1, 2, 4])
encoding = st.selectbox("Encoding Format", ["plain", "base64", "hex", "binary"])
password = st.text_input("Password (optional)", type="password")

if operation == "Encode":
    message = st.text_area("Enter message to hide")
    if uploaded_image and message:
        with open("temp_input.png", "wb") as f:
            f.write(uploaded_image.getvalue())
        output_path = "encoded_output.png"
        embed("temp_input.png", message, bits=int(bits), password=password, output_path=output_path)
        st.success("✅ Message encoded successfully!")
        st.image(output_path)
        with open(output_path, "rb") as f:
            st.download_button("📥 Download Encoded Image", data=f, file_name="encoded_image.png", mime="image/png")

elif operation == "Decode":
    if uploaded_image:
        with open("temp_input.png", "wb") as f:
            f.write(uploaded_image.getvalue())
        result = extract("temp_input.png", bits=int(bits), password=password)
        st.success("✅ Decoded Message:")
        st.code(result)
