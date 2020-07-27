import jsonpickle
class ResultStorer():
    

    def __init__(self, storage_file_name):
        self._storage_file_name = storage_file_name
        self._storage_file = open(self._storage_file_name, 'a')

    def store(self, analysis_target, analysis_results):
        rsu = ResultStorageUnit(analysis_target, analysis_results)
        rsu_json = jsonpickle.encode(rsu)
        self._storage_file.write("{}\n".format(rsu_json))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._storage_file.close()

class ResultStorageUnit():

    def __init__(self, analysis_target, analysis_results):
        self.analysis_target = analysis_target
        self.analysis_results = analysis_results
