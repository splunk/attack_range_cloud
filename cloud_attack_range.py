import os
import sys
import argparse
from modules import logger
from pathlib import Path
from modules.TerraformController import TerraformController
from modules.CustomConfigParser import CustomConfigParser


# need to set this ENV var due to a OSX High Sierra forking bug
# see this discussion for more details: https://github.com/ansible/ansible/issues/34056#issuecomment-352862252
os.environ['OBJC_DISABLE_INITIALIZE_FORK_SAFETY'] = 'YES'

VERSION = 1


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="starts a cloud attack range ready to collect attack data into splunk")
    parser.add_argument("-a", "--action", required=False, choices=['build', 'destroy', 'simulate', 'stop', 'resume'],
                        help="action to take on the range, defaults to \"build\", build/destroy/simulate/stop/resume allowed")
    parser.add_argument("-st", "--simulation_technique", required=False, type=str, default="",
                        help="comma delimited list of MITRE ATT&CK technique ID to simulate in the attack_range, example: T1117, T1118, requires --simulation flag")
    parser.add_argument("-c", "--config", required=False, default="cloud_attack_range.conf",
                        help="path to the configuration file of the attack range")
    parser.add_argument("-lm", "--list_machines", required=False, default=False, action="store_true", help="prints out all available machines")
    parser.add_argument("-v", "--version", default=False, action="store_true", required=False,
                        help="shows current attack_range version")

    # parse them
    args = parser.parse_args()
    ARG_VERSION = args.version
    action = args.action
    config = args.config
    simulation_techniques = args.simulation_technique
    list_machines = args.list_machines

    print("""
starting program loaded for B1 battle droid
          ||/__'`.
          |//()'-.:
          |-.||
          |o(o)
          |||\\\  .==._
          |||(o)==::'
           `|T  ""
            ()
            |\\
            ||\\
            ()()
            ||//
            |//
           .'=`=.
    """)

    # parse config
    attack_range_config = Path(config)
    if attack_range_config.is_file():
        print("attack_range is using config at path {0}".format(attack_range_config))
        configpath = str(attack_range_config)
    else:
        print("ERROR: attack_range failed to find a config file at {0} or {1}..exiting".format(attack_range_config))
        sys.exit(1)

    # Parse config
    parser = CustomConfigParser()
    config = parser.load_conf(configpath)

    log = logger.setup_logging(config['log_path'], config['log_level'])
    log.info("INIT - attack_range v" + str(VERSION))

    if ARG_VERSION:
        log.info("version: {0}".format(VERSION))
        sys.exit(0)

    # identfy not possible argument combination

    controller = TerraformController(config, log)

    if list_machines:
        controller.list_machines()
        sys.exit(0)

    if action == 'build':
        controller.build()

    if action == 'destroy':
        controller.destroy()

    if action == 'stop':
        controller.stop()

    if action == 'resume':
        controller.resume()

    if action == 'simulate':
        controller.simulate(target, simulation_techniques, simulation_atomics)

    if action == 'test':
        controller.test(test_file)


# rnfgre rtt ol C4G12VPX
