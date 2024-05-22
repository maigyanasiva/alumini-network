import streamlit as st
from pymongo import MongoClient
import bcrypt
from bson.objectid import ObjectId

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client.alumni_network
users_collection = db.users
chats_collection = db.chats

# Helper function to check if user exists
def user_exists(email):
    return users_collection.find_one({"email": email})

# Helper function to verify password
def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'user' not in st.session_state:
    st.session_state['user'] = None

# Streamlit App
st.title("Alumni Network Platform")

menu = ["Home", "Register", "Login", "Profile", "Search", "Chat", "Logout"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Home":
    st.subheader("Welcome to the Alumni Network Platform")

elif choice == "Register":
    st.subheader("Register")

    name = st.text_input("Full Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type='password')
    batch = st.text_input("Batch")
    major = st.text_input("Major")

    if st.button("Register"):
        if user_exists(email):
            st.error("User already exists. Please login.")
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            users_collection.insert_one({"name": name, "email": email, "password": hashed_password, "batch": batch, "major": major, "achievements": []})
            st.success("You have successfully registered. Please login.")

elif choice == "Login":
    st.subheader("Login")

    email = st.text_input("Email")
    password = st.text_input("Password", type='password')

    if st.button("Login"):
        user = user_exists(email)
        if user and verify_password(user['password'], password):
            st.session_state['logged_in'] = True
            st.session_state['user'] = user
            st.success("Logged in successfully")
            st.experimental_rerun()
        else:
            st.error("Invalid email or password")

elif choice == "Profile":
    if st.session_state['logged_in']:
        st.subheader("Profile")

        user = st.session_state['user']
        st.write(f"Name: {user['name']}")
        st.write(f"Email: {user['email']}")
        st.write(f"Batch: {user['batch']}")
        st.write(f"Major: {user['major']}")
        st.write("Achievements:")
        for achievement in user.get('achievements', []):
            st.write(f"- {achievement}")

        st.subheader("Update Profile")
        new_name = st.text_input("New Name", user['name'])
        new_batch = st.text_input("New Batch", user['batch'])
        new_major = st.text_input("New Major", user['major'])
        new_achievement = st.text_input("New Achievement")

        if st.button("Update Profile"):
            update_fields = {"name": new_name, "batch": new_batch, "major": new_major}
            if new_achievement:
                update_fields["achievements"] = user.get('achievements', []) + [new_achievement]
            users_collection.update_one({"_id": user['_id']}, {"$set": update_fields})
            user = users_collection.find_one({"_id": ObjectId(user['_id'])})
            st.session_state['user'] = user
            st.success("Profile updated successfully")
            st.experimental_rerun()
    else:
        st.warning("Please login to view your profile")

elif choice == "Search":
    st.subheader("Search Alumni")

    search_name = st.text_input("Search by Name")
    search_batch = st.text_input("Search by Batch")
    search_major = st.text_input("Search by Major")

    if st.button("Search"):
        query = {}
        if search_name:
            query["name"] = {"$regex": search_name, "$options": "i"}
        if search_batch:
            query["batch"] = {"$regex": search_batch, "$options": "i"}
        if search_major:
            query["major"] = {"$regex": search_major, "$options": "i"}
        
        results = users_collection.find(query)
        for result in results:
            st.write(f"Name: {result['name']}")
            st.write(f"Email: {result['email']}")
            st.write(f"Batch: {result['batch']}")
            st.write(f"Major: {result['major']}")
            st.write("Achievements:")
            for achievement in result.get('achievements', []):
                st.write(f"- {achievement}")
            st.write("---")

elif choice == "Chat":
    if st.session_state['logged_in']:
        st.subheader("Chat with Alumni")

        all_users = users_collection.find({"_id": {"$ne": st.session_state['user']['_id']}})
        user_dict = {user['_id']: user['name'] for user in all_users}
        
        selected_user_id = st.selectbox("Select User to Chat With", list(user_dict.keys()), format_func=lambda x: user_dict[x])

        message = st.text_area("Message")
        if st.button("Send Message"):
            chats_collection.insert_one({"from": st.session_state['user']['_id'], "to": selected_user_id, "message": message})
            st.success("Message sent successfully")

        st.subheader("Chat History")
        chat_history = chats_collection.find({"$or": [{"from": st.session_state['user']['_id'], "to": selected_user_id}, {"from": selected_user_id, "to": st.session_state['user']['_id']}]})
        for chat in chat_history:
            from_user = user_dict[chat['from']] if chat['from'] != st.session_state['user']['_id'] else "You"
            to_user = user_dict[chat['to']] if chat['to'] != st.session_state['user']['_id'] else "You"
            st.write(f"{from_user} to {to_user}: {chat['message']}")
            st.write("---")
    else:
        st.warning("Please login to chat with other alumni")

elif choice == "Logout":
    if st.session_state['logged_in']:
        st.session_state['logged_in'] = False
        st.session_state['user'] = None
        st.success("Logged out successfully")
        st.experimental_rerun()
    else:
        st.warning("You are not logged in")
