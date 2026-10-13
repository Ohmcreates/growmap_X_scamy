"""
Train Model Entry Point
Executes the model training pipeline to generate phishing_model.pkl.
"""

from fetch_and_train import train_and_save_model

if __name__ == '__main__':
    train_and_save_model()
