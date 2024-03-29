class AnalysisTarget():
    '''
    An object to store information of the target file to be analyzed.
    '''
    def __init__(self, full_file_path: str, file_name: str, file_size: int, file_md5: str):
        '''
        Parameters:
        full_file_path : str
            The absolute path of the file to analyze
        file_name : str
            The basename of the file to analyze
        file_size : int
            The size of the file to analyze, in bytes
        file_md5 : str
            The MD5 hash of the file to analyze

        '''
        self.full_file_path = full_file_path
        self.file_name = file_name
        self.file_size = file_size
        self.file_md5 = file_md5


    def __str__(self):
        return "<AnalysisTarget {} ({} bytes) MD5={}>".format(self.full_file_path, self.file_size, self.file_md5)

    def __eq__(self, o):
        if o is None:
            return False
        if not isinstance(o, AnalysisTarget):
            return False
        return self.full_file_path == o.full_file_path and self.file_name == o.file_name and self.file_size == o.file_size and self.file_md5 == o.file_md5

    def __hash__(self):
        return hash("{}{}{}{}".format(self.full_file_path, self.file_name, self.file_size, self.file_md5))
        
