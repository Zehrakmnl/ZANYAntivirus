
import yara
import os

def fscan(path):
    rules = yara.compile('/home/zehra/Desktop/son son son hali2/trojan.yar') # windowsta değiştirilecek untuma!!

    target = path#'/home/zehra/Desktop/trojan.txt'#C:/Users/Asus/Desktop/text.txt'

    matches = rules.match(target)

    if matches:
        print("File matches trojan behavior rule! -Dosya trojan davranış kuralıyla eşleşiyor!-")
        for match in matches:
            print(path," Konumunda ", " <=> ",match, " versiyonda zararlı yazılım tespit edildi !! ")
            print(match.strings)
    else:
        print("CLEAN")

def scan():
    def scan(path):
        rules = yara.compile('/home/zehra/Desktop/son son son hali2/trojan.yar')
        filePaths = []
        target = '/home/zehra/Desktop/trojan.txt'
        for root, dirs, files in os.walk(path): # os.walk() her dizin için 3-tuple verir (root, dirs,files)
            for file in files:
                filePath = os.path.join(root, file)
                #print(os.system(f"{os.path.join(root, file)}"))
                matches = rules.match(target)
                if matches:
                    for mat in matches:                        
                        for string in mat.strings:  
                            if string[2].decode() in file:
                                #print(f"===>{os.path.join(root, file)} ")
                                print("File matches trojan behavior rule! -Dosya trojan davranış kuralıyla eşleşiyor!-")
                                filePaths.append(os.path.join(root, file))
                                for rule in matches:
                                    print(mat," => ",{filePath})
                                    break
                                
                                try:
                                    #os.system(f"del /f {os.path.join(root, file)}")
                                    print(f"succesfuly deleted")
                                    break
                                except Exception as e:
                                    print(f"Error  {str(e)}")
        return filePaths
        
    scan('/home/')



