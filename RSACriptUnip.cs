using System;
using System.Text;
using System.Collections.Generic;
using System.Numerics;

namespace CriptografiaRSA
{
    public class RSACriptUnip
    {
        // String fixo sem base matematica apenas para separar duas variaveis base64 dentro de uma unica string
        static string SEPARADOR_CHAVES = "+F+D=UNIP2017+=";

        // Propriedade chave pública E
        public int eValue { get; set; }

        // Primeira chave pública
        public int CalcularN(int p, int q)
        {
            int n = 0;

            // Verifica se possuímos p e q recebidos
            if (p != 0 && q != 0)
            {
                // Multiplica os dois números primos para gerar a chave pública
                n = p * q;
            }

            // Armazena o valor da chave pública N
            return n;
        }

        public int CalcularTotienteN(int p, int q)
        {
            int totienteN = 0;

            // Verifica se possuímos p e q recebidos
            if (p != 0 && q != 0)
            {
                // Calcula a função totiente de n
                totienteN = (p - 1) * (q - 1);
            }

            return totienteN;
        }

        // Segunda chave pública
        public void CalcularE(int totienteN)
        {
            int e = 0;
            List<int> divisoresE = new List<int>();
            List<int> divisoresTotienteN = new List<int>();
            bool podeSer = false;
            Random numRandomico = new Random();
            int countMenor = 0;
            int countMaior = 0;
            int numMenorAux = 0;
            int numMaiorAux = 0;

            // Looping gerando o valor 'e' tal que 1 < e < totienteN
            for (e = 2; e < totienteN; e++)
            {
                // Se o máximo divisor comum entre 'e' e 'totienteN' for 1
                if (mdc(e, totienteN) == 1)
                {
                    // Significa que achamos o valor 'e' que obedece à condição desejada
                    break;
                }
            }

            // Enquanto o número escolhido para E não puder ser utilizado, recalcula
            while (podeSer == false)
            {
                // Pega todos os divisores de e
                divisoresE = RetornaDivisores(e);

                // Pega todos os divisores de totiente de N
                divisoresTotienteN = RetornaDivisores(totienteN);

                // Verifica qual dos 2 arrays possuem menores elementos para poder utilizar como base para o loop
                countMenor = (divisoresE.Count > divisoresTotienteN.Count ? divisoresTotienteN.Count : divisoresE.Count);

                // Pega qual possui maiores elementos
                countMaior = (divisoresE.Count > divisoresTotienteN.Count ? divisoresE.Count : divisoresTotienteN.Count);
                // Loop para verificar se E e totienteN possuem divisores comuns
                for (int i = 0; i < countMenor; i++)
                {
                    for (int j = 0; j < countMaior; j++)
                    {
                        // Redescobre qual array possui menores elementos
                        if (countMenor == divisoresE.Count)
                        {
                            // Os divisores de E possuem os menores elementos
                            // Armazena o valor do primeiro index i e o numero do laço atual j
                            numMenorAux = divisoresE[i];
                            numMaiorAux = divisoresTotienteN[j];
                        }
                        else
                        {
                            // Os divisores de totienteN possuem os menores elementos
                            // Armazena o valor do primeiro index i e o numero do laço atual j
                            numMenorAux = divisoresTotienteN[i];
                            numMaiorAux = divisoresE[j];
                        }

                        // 'e' e 'totienteN' possuem divisores em comum? (Com excessão de 1)
                        if (numMenorAux == numMaiorAux && numMenorAux != 1)
                        {
                            // Caso possuam, seta que o valor de 'e' criado não pode ser utilizado e refaz o while (finaliza o loop menor para que possa finalizar o loop maior)
                            podeSer = false;
                            break;
                        }
                        else
                        {
                            // Até que o loop completo termine, ainda não houve divisores em comum. Ou seja, até agora o valor de 'e' pode ser utilizado
                            podeSer = true;
                        }
                    }

                    // Se encontramos divisores em comum, 'e' atual não pode ser utilizado
                    if (podeSer == false)
                    {
                        // Finaliza o loop maior
                        break;
                    }
                }
            }

            // Armazena o valor da chave pública E
            eValue = e;
        }

        // Terceira chave privada (p e q são as duas primeiras)
        public int CalcularInversoD(int totienteN)
        {
            int d = 0;

            // Calcula o inverso multiplicativo de e:totienteN.
            for (d = 1; d <= totienteN; d++)
            {
                // 'd' satisfaz a seguinte condição? (d * e) % totienteN == 1
                if ((d * eValue) % totienteN == 1)
                {
                    // Então 'd' é o inverso multiplicativo e, portanto, não precisa mais continuar a busca. Finaliza o loop.
                    break;
                }
            }

            return d;
        }

        static List<int> RetornaDivisores(int numero)
        {
            List<int> divisoresNumero = new List<int>();
            int resto = 0;

            // Loop para calcular todos os divisores do numero
            for (int i = 1; i <= numero; i++)
            {
                // Pega o resto da divisão
                resto = numero % i;

                // Se i é um divisor
                if (resto == 0)
                {
                    // Adiciona no array de divisores do numero
                    divisoresNumero.Add(i);
                }
            }

            return divisoresNumero;
        }

        public string RetornaChavePublica(int e, int n)
        {
            StringBuilder chavePublica = new StringBuilder("");
            string eBase64 = "";
            string nBase64 = "";

            // Obtem os bytes dos parametros
            byte[] eBytes = System.Text.Encoding.UTF8.GetBytes(e.ToString());
            byte[] nBytes = System.Text.Encoding.UTF8.GetBytes(n.ToString());

            // Converte para base 64
            eBase64 = System.Convert.ToBase64String(eBytes);
            nBase64 = System.Convert.ToBase64String(nBytes);

            // Formata a chave publica combinando os textos necessários (n + separador + e)
            chavePublica.Append("-----BEGIN RSA PUBLIC KEY-----");
            chavePublica.Append(nBase64);
            chavePublica.Append(SEPARADOR_CHAVES);
            chavePublica.Append(eBase64);
            chavePublica.Append("-----END RSA PUBLIC KEY-----");

            return chavePublica.ToString();
        }

        public string RetornaChavePrivada(int d, int n)
        {
            StringBuilder chavePrivada = new StringBuilder();
            string dBase64 = "";
            string nBase64 = "";

            // Obtem os bytes dos parametros
            byte[] dBytes = System.Text.Encoding.UTF8.GetBytes(d.ToString());
            byte[] nBytes = System.Text.Encoding.UTF8.GetBytes(n.ToString());

            // Converte para base 64
            dBase64 = System.Convert.ToBase64String(dBytes);
            nBase64 = System.Convert.ToBase64String(nBytes);

            // Formata a chave privada combinando os textos necessários (n + separador + d)
            chavePrivada.Append("-----BEGIN RSA PRIVATE KEY-----");
            chavePrivada.Append(nBase64);
            chavePrivada.Append(SEPARADOR_CHAVES);
            chavePrivada.Append(dBase64);
            chavePrivada.Append("-----END RSA PRIVATE KEY-----");

            return chavePrivada.ToString();
        }

        public string Criptografar(string textoSimples, string chavePublica)
        {
            string textoCifrado = "";
            int n = 0;
            int e = 0;
            string[] chaveFragmentada;
            string nBase64 = "";
            string eBase64 = "";
            byte[] nBytes;
            byte[] eBytes;
            char[] caracteres;
            int intAux;
            BigInteger numeroNovoAux;
            byte[] textoCifradoBytes;

            try
            {
                // Cria o array de separadores para realizar o split da chave publica e pega um array contendo 'n' e 'e'
                string[] separadores = { "-----BEGIN RSA PUBLIC KEY-----", SEPARADOR_CHAVES, "-----END RSA PUBLIC KEY-----" };
                chaveFragmentada = chavePublica.Split(separadores, StringSplitOptions.RemoveEmptyEntries);
                nBase64 = chaveFragmentada[0];
                eBase64 = chaveFragmentada[1];

                // Obtem os bytes de 'n' e 'e' e converte para string, passando para inteiros
                nBytes = System.Convert.FromBase64String(nBase64);
                eBytes = System.Convert.FromBase64String(eBase64);
                n = int.Parse(System.Text.Encoding.UTF8.GetString(nBytes));
                e = int.Parse(System.Text.Encoding.UTF8.GetString(eBytes));

                // Passa o texto simples para um array contendo cada um dos caracteres
                caracteres = textoSimples.ToCharArray();

                // Loop por todos os caracteres do texto simples
                for (int i = 0; i < caracteres.Length; i++)
                {
                    // Converte a letra para ASCII
                    intAux = Convert.ToInt32(caracteres[i]);

                    // Realiza a conta: (intAux ^ e) % n
                    numeroNovoAux = BigInteger.ModPow(intAux, e, n);

                    // Quando for o primeiro número
                    if (textoCifrado == "")
                    {
                        // Apenas adiciona o numero novo
                        textoCifrado += numeroNovoAux.ToString();
                    }
                    else
                    {
                        // Coloca um caractere de separacao e adiciona o numero novo
                        textoCifrado += "-" + numeroNovoAux.ToString();
                    }
                }

                // Converte o texto para base64
                textoCifradoBytes = System.Text.Encoding.UTF8.GetBytes(textoCifrado);

                return System.Convert.ToBase64String(textoCifradoBytes);
            }
            catch
            {
                return "Erro ao criptografar texto. Gere uma chave nova e tente novamente.";
            }
        }

        public string Descriptografar(string textoCifrado, string chavePrivada)
        {
            string textoOriginal = "";
            int n = 0;
            int d = 0;
            string[] chaveFragmentada;
            string nBase64 = "";
            string dBase64 = "";
            byte[] nBytes;
            byte[] dBytes;
            string[] arrayTextoCifradoSeparado;
            BigInteger intAux;
            BigInteger numeroNovoAux;
            byte[] textoOriginalBytes;

            try
            {
                // Cria o array de separadores para realizar o split da chave publica e pega um array contendo 'n' e 'd'
                string[] separadores = { "-----BEGIN RSA PRIVATE KEY-----", SEPARADOR_CHAVES, "-----END RSA PRIVATE KEY-----" };
                chaveFragmentada = chavePrivada.Split(separadores, StringSplitOptions.RemoveEmptyEntries);
                nBase64 = chaveFragmentada[0];
                dBase64 = chaveFragmentada[1];

                // Obtem os bytes de 'n' e 'd' e converte para string, passando para inteiros
                nBytes = System.Convert.FromBase64String(nBase64);
                dBytes = System.Convert.FromBase64String(dBase64);
                n = int.Parse(System.Text.Encoding.UTF8.GetString(nBytes));
                d = int.Parse(System.Text.Encoding.UTF8.GetString(dBytes));

                // Converte o texto cifrado da base64 para UTF8 decimal
                textoOriginalBytes = System.Convert.FromBase64String(textoCifrado);

                // Realiza um split do texto cifrado, eliminando os separador "-"
                arrayTextoCifradoSeparado = System.Text.Encoding.UTF8.GetString(textoOriginalBytes).Split(new[] { '-' });

                // Loop para percorrer todas as cifras
                for (int i = 0; i < arrayTextoCifradoSeparado.Length; i++)
                {
                    // Pega o número armazenado na string auxiliar
                    intAux = BigInteger.Parse(arrayTextoCifradoSeparado[i]);

                    // Realiza a conta: (intAux ^ d) % n
                    numeroNovoAux = BigInteger.ModPow(intAux, d, n);

                    // Converte de número para caractere pela tabela ASCII
                    textoOriginal += Convert.ToChar((int)numeroNovoAux);
                }

                return textoOriginal;
            }
            catch
            {
                return "Erro ao descriptografar texto. Gere uma chave nova e tente novamente.";
            }
        }

        // Método recursivo que calcula o máximo divisor comum entre os dois parâmetros
        public BigInteger mdc(BigInteger a, BigInteger b)
        {
            BigInteger aux = 0;

            while (true)
            {
                aux = a % b;

                if (aux == 0)
                {
                    return b;
                }

                a = b;
                b = aux;
            }
        }
    }
}
