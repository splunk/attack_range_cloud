
from abc import ABC, abstractmethod

class IEnvironmentController(ABC):


    def __init__(self, config, log):
        self.config = config
        self.log = log
        super().__init__()

    @abstractmethod
    def build(self):
        pass

    @abstractmethod
    def destroy(self):
        pass

    @abstractmethod
    def stop(self):
        pass

    @abstractmethod
    def resume(self):
        pass

    @abstractmethod
    def simulate(self, simulation_techniques,attack_chain_file,clean_up):
        pass

    @abstractmethod
    def test(self, test_file):
        pass

    @abstractmethod
    def list_machines(self):
        pass

    @abstractmethod
    def dump_attack_data(self, dump_name, last_sim):
        pass

    @abstractmethod
    def replay_attack_data(self, dump_name, dump):
        pass
