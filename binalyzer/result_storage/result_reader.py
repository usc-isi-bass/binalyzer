import jsonpickle
class ResultReader():
    

    def __init__(self, storage_file_name):
        self._storage_file_name = storage_file_name
        self._storage_file = open(self._storage_file_name, 'r')

    def read(self):
        for line in self._storage_file:
            line = line.strip()
            rsu = jsonpickle.decode(line)
            yield rsu

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._storage_file.close()
