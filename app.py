import streamlit as st
from analyzer import analyze_code


# Page configuration
st.set_page_config(
    page_title="AI Code Quality & Security Analyzer",
    page_icon="🛡️",
    layout="wide"
)


# Title
st.title("🛡️ AI-Powered Code Quality & Security Analyzer")
st.caption("Developed by Abhi Kamboj | BTech CSE")

st.write(
    "Analyze your Python code for quality problems and common security risks."
)

st.divider()


# Code input
st.subheader("💻 Enter Your Python Code")

code = st.text_area(
    "Paste your code below:",
    height=300,
    placeholder="Example:\npassword = '12345'\nx = eval(input())\nprint(x)"
)


# Analyze button
if st.button("🔍 Analyze Code"):

    if not code.strip():
        st.warning("Please enter some code first.")

    else:

        result = analyze_code(code)

        quality_score = result["quality_score"]
        security_score = result["security_score"]

        st.subheader("📊 Analysis Results")

        # Scores
        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Code Quality Score",
                f"{quality_score}/100"
            )

        with col2:
            st.metric(
                "Security Score",
                f"{security_score}/100"
            )

        st.divider()

        # Quality issues
        st.subheader("⚠️ Code Quality Issues")

        if result["issues"]:
            for issue in result["issues"]:
                st.warning(issue)
        else:
            st.success("No major quality issues found!")

        # Security issues
        st.subheader("🔐 Security Issues")

        if result["security_issues"]:
            for issue in result["security_issues"]:
                st.error(issue)
        else:
            st.success("No common security issues detected!")

        # Overall result
        st.divider()

        overall_score = (quality_score + security_score) // 2

        st.subheader("🏆 Overall Score")

        st.progress(overall_score / 100)

        st.write(f"### {overall_score}/100")