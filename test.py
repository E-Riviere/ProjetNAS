import yaml

as_file = open("as.yml", "r")
as_dic = yaml.safe_load(as_file)
routeur_file = open("routeur.yml", "r")
routeur_dic = yaml.safe_load(routeur_file)
print(routeur_dic)
