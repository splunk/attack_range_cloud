import os
import sys
import argparse
from modules import logger
from modules import configuration
from pathlib import Path
from modules.TerraformController import TerraformController
from modules.CustomConfigParser import CustomConfigParser


# need to set this ENV var due to a OSX High Sierra forking bug
# see this discussion for more details: https://github.com/ansible/ansible/issues/34056#issuecomment-352862252
os.environ['OBJC_DISABLE_INITIALIZE_FORK_SAFETY'] = 'YES'

VERSION = 1

def init(args):
    config = args.config
    print("""
starting program loaded for B1 battle droid

          .-~~~-.
  .- ~ ~-(       )_ _
 /                     ~ -.
|   Cloud Attack Range     \
 \                         .'
   ~- . _____________ . -~
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
    print (attack_range_config)
    if attack_range_config.is_file():
        print("attack_range is using config at path {0}".format(attack_range_config))
        configpath = str(attack_range_config)
    else:
        print("ERROR: attack_range failed to find a config file")
        sys.exit(1)

    # Parse config
    parser = CustomConfigParser()
    config = parser.load_conf(configpath)

    log = logger.setup_logging(config['log_path'], config['log_level'])
    log.info("INIT - attack_range v" + str(VERSION))

    # if ARG_VERSION:
    #     log.info("version: {0}".format(VERSION))
    #     sys.exit(0)

    return TerraformController(config, log), config, log

def configure(args):
    configuration.new(args.config)

def show(args):
    controller, _, _ = init(args)
    if args.machines:
        controller.list_machines()

def simulate(args):
    controller, config, _ = init(args)
    target = args.target
    simulation_techniques = args.simulation_technique
    simulation_atomics = args.simulation_atomics
    # lets give CLI priority over config file for pre-configured techniques
    if simulation_techniques:
        pass
    else:
        simulation_techniques = config['art_run_techniques']

    if not simulation_atomics:
        simulation_atomics = 'no'
    return controller.simulate(target, simulation_techniques, simulation_atomics)

def dump(args):
    controller, _, _ = init(args)
    controller.dump_attack_data(args.dump_name, args.last_sim)


def replay(args):
    controller, _, _ = init(args)
    controller.replay_attack_data(args.dump_name, args.dump)


def build(args):
    controller, _, _ = init(args)
    controller.build()


def destroy(args):
    controller, _, _ = init(args)
    controller.destroy()


def stop(args):
    controller, _, _ = init(args)
    controller.stop()


def resume(args):
    controller, _, _ = init(args)
    controller.resume()


def test(args):
    controller, _, _ = init(args)
    return controller.test(args.test_file)

def main(args):
    # grab arguments
    parser = argparse.ArgumentParser(
        description="Use `attack_range.py action -h` to get help with any Attack Range action")
    parser.add_argument("-c", "--config", required=False, default="cloud_attack_range.conf",
                        help="path to the configuration file of the attack range")
    parser.add_argument("-v", "--version", default=False, action="version", version="version: {0}".format(VERSION),
                        help="shows current attack_range version")
    parser.set_defaults(func=lambda _: parser.print_help())  

    actions_parser = parser.add_subparsers(title="Attack Range actions", dest="action")
    configure_parser = actions_parser.add_parser("configure", help="configure a new attack range")
    build_parser = actions_parser.add_parser("build", help="Builds attack range instances")
    simulate_parser = actions_parser.add_parser("simulate", help="Simulates attack techniques")
    destroy_parser = actions_parser.add_parser("destroy", help="destroy attack range instances")
    stop_parser = actions_parser.add_parser("stop", help="stops attack range instances")
    resume_parser = actions_parser.add_parser("resume", help="resumes previously stopped attack range instances")
    show_parser = actions_parser.add_parser("show", help="list machines")
    test_parser = actions_parser.add_parser("test")
    dump_parser = actions_parser.add_parser("dump", help="dump locally logs from attack range instances")
    replay_parser = actions_parser.add_parser("replay", help="replay dumps into the Splunk Enterprise server")

    # Build arguments
    build_parser.set_defaults(func=build)

    # Destroy arguments
    destroy_parser.set_defaults(func=destroy)

    # Stop arguments
    stop_parser.set_defaults(func=stop)

    # Resume arguments
    resume_parser.set_defaults(func=resume)

    # Configure arguments
    configure_parser.add_argument("-c", "--config", required=False, type=str, default='attack_range.conf',
                                    help="provide path to write configuration to")
    configure_parser.set_defaults(func=configure)

    # Simulation arguments
    simulate_parser.add_argument("-t", "--target", required=True,
                                 help="target for attack simulation. Use the name of the aws EC2 name")
    simulate_parser.add_argument("-st", "--simulation_technique", required=False, type=str, default="",
                                 help="comma delimited list of MITRE ATT&CK technique ID to simulate in the "
                                      "attack_range, example: T1117, T1118, requires --simulation flag")
    simulate_parser.add_argument("-sa", "--simulation_atomics", required=False, type=str, default="",
                                 help="specify dedicated Atomic Red Team atomics to simulate in the attack_range, "
                                      "example: Regsvr32 remote COM scriptlet execution for T1117")
    simulate_parser.set_defaults(func=simulate)

    # # Dump  Arguments
    # dump_parser.add_argument("-dn", "--dump_name", required=True,
    #                          help="name for the dumped attack data")
    # dump_parser.add_argument("--last-sim", required=False, action='store_true',
    #                          help="overrides dumps.yml time and dumps from the start of previous simulation")
    # dump_parser.set_defaults(func=dump)

    # # Replay Arguments
    # replay_parser.add_argument("-dn", "--dump_name", required=True,
    #                            help="name for the dumped attack data")
    # replay_parser.add_argument("--dump", required=False,
    #                     help="name of the dump as defined in attack_data/dumps.yml")
    # replay_parser.set_defaults(func=replay)

    # # Test Arguments
    # test_parser.add_argument("-tf", "--test_file", required=True,
    #                          type=str, default="", help='test file for test command')
    # test_parser.set_defaults(func=test)

    # Show arguments
    show_parser.add_argument("-m", "--machines", required=False, default=False,
                             action="store_true", help="prints out all available machines")
    show_parser.set_defaults(func=show, machines=True)

    # # parse them
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:])


#     parser = argparse.ArgumentParser(description="starts a cloud attack range ready to collect attack data into splunk")
#     parser.add_argument("-a", "--action", required=False, choices=['build', 'destroy', 'simulate', 'stop', 'resume', 'dump'], default="",
#                         help="action to take on the range, defaults to \"build\", build/destroy/simulate/stop/resume allowed")
#     parser.add_argument("-st", "--simulation_technique", required=False, type=str, default="",
#                         help=" MITRE ATT&CK technique ID to simulate in the attack_range, example: T1098, requires action simulate")
#     parser.add_argument("-sf", "--simulation_file", required=False, type=str, default="",
#                         help="path to simulation file, e.g. leonidas/definitions/persistence/create_iam_group.yml")
#     parser.add_argument("-sv", "--simulation_vars", required=False, type=str, default="",
#                         help="comma separated list of simulation vars, --simulation_vars 'user=test, password=test'")
#     parser.add_argument("-f", "--force", required=False, default=False, action="store_true",
#                         help="directly run the attack without popup")
#     parser.add_argument("-dn", "--dump_name", required=False, default="",
#                         help="name for the dumped attack data")
#     parser.add_argument("-c", "--config", required=False, default="cloud_attack_range.conf",
#                         help="path to the configuration file of the attack range")
#     parser.add_argument("-lm", "--list_machines", required=False, default=False, action="store_true", help="prints out all available machines")
#     parser.add_argument("-v", "--version", default=False, action="store_true", required=False,
#                         help="shows current attack_range version")

#     # parse them
#     args = parser.parse_args()
#     ARG_VERSION = args.version
#     action = args.action
#     config = args.config
#     simulation_technique = args.simulation_technique
#     simulation_file = args.simulation_file
#     list_machines = args.list_machines
#     force = args.force
#     simulation_vars = args.simulation_vars
#     dump_name = args.dump_name


#     # identfy not allowed argument combination
#     if action == "simulate" and (simulation_file == "" and simulation_technique == ""):
#         log.error("ERROR: action simulate need either flag --simulation_file or --simulation_technique")
#         sys.exit(1)

#     if action == "dump" and dump_name == "":
#         log.error("ERROR: action dump need the flag --dump_name")
#         sys.exit(1)

#     if action == "" and not list_machines:
#         log.error('ERROR: flag --action is needed.')
#         sys.exit(1)

#     if config['attack_range_password'] == 'I-l1ke-Attack-Range!':
#         log.error('ERROR: please change attack_range_password in attack_range.conf')
#         sys.exit(1)

#     if len(config['key_name']) > 20:
#         log.error('ERROR: your key_name is too long. Please create a shorter key_name. Maximum number of characters are 20.')
#         sys.exit(1)

#     controller = TerraformController(config, log)

#     if list_machines:
#         controller.list_machines()
#         sys.exit(0)

#     if action == 'build':
#         controller.build()

#     if action == 'destroy':
#         controller.destroy()

#     if action == 'stop':
#         controller.stop()

#     if action == 'resume':
#         controller.resume()

#     if action == 'simulate':
#         controller.simulate(simulation_technique, simulation_file, force, simulation_vars)

#     if action == 'dump':
#         controller.dump(dump_name)


# # rnfgre rtt ol C4G12VPX
