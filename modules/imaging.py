def create_image(source, destination):
    try:
        with open(source, 'rb') as f_src, open(destination, 'wb') as f_dest:
            f_dest.write(f_src.read())
        return True
    except Exception as e:
        print(f"Error imaging: {e}")
        return False