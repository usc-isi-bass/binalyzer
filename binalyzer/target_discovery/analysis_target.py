class AnalysisTarget():
    def __init__(self, full_file_path, file_name, file_size, file_md5):
        self.full_file_path = full_file_path
        self.file_name = file_name
        self.file_size = file_size
        self.file_md5 = file_md5


    def __str__(self):
        return "<AnalysisTarget {} ({} bytes) MD5={}>".format(self.full_file_path, self.file_size, self.file_md5)
        
