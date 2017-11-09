using System;
using System.Text;
using System.Collections.Generic;
using System.Numerics;

namespace CriptografiaRSA
{
    public class RSACriptUnip
    {
            // Propriedade chave pública E
        public int Key_Encrypt { get; set; }

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

            // Verifica se possuímos o totiente de N
            if (totienteN != 0)
            {
                // Enquanto o número escolhido para E não puder ser utilizado, recalcula
                while (podeSer == false)
                {
                    // Escolhe um número aleatório que satisfaça 1 > e > totienteN
                    e = numRandomico.Next(2, totienteN);

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
            }

            // Armazena o valor da chave pública E
            Key_Encrypt = e;
        }

        // Terceira chave privada (p e q são as duas primeiras)
        public int CalcularInversoD(int totienteN)
        {
            int d = 0;

            // Calcula o inverso multiplicativo de e:totienteN.
            for (d = 1; d <= totienteN; d++)
            {
                // 'd' satisfaz a seguinte condição? (d * e) % totienteN == 1
                if ((d * Key_Encrypt) % totienteN == 1)
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

        public string Criptografar(string textoSimples, int key_Encrypt, int moduloN)
        {
            char[] caracteres;
            int intAux;
            string stringCifraCompleta = "";
            BigInteger numeroNovo;

            // Passa o texto simples para um array contendo cada um dos caracteres
            caracteres = textoSimples.ToCharArray();

            // Loop por todos os caracteres do texto simples
            for (int i = 0; i < caracteres.Length; i++)
            {
                // Converte a letra para ASCII
                intAux = Convert.ToInt32(caracteres[i]);

                // Realiza a conta: (intAux ^ key_Encrypt) % moduloN
                numeroNovo = BigInteger.ModPow(intAux, key_Encrypt, moduloN);

                // Quando for o primeiro número
                if (stringCifraCompleta == "")
                {
                    // Apenas adiciona o numero novo
                    stringCifraCompleta += numeroNovo.ToString();
                }
                else
                {
                    // Coloca um caractere de separacao e adiciona o numero novo
                    stringCifraCompleta += "-" + numeroNovo.ToString();
                }
            }

            // Retorna o texto cifrado
            return stringCifraCompleta;
        }

        public string Descriptografar(string textoCifrado, int key_Descrypt, int moduloN)
        {
            string[] arrayTextoCifradoSeparado;
            BigInteger numCifradoAux;
            BigInteger numOriginal;
            string textoOriginal = "";

            // Realiza um split do texto cifrado, eliminando os separador "-"
            arrayTextoCifradoSeparado = textoCifrado.Split(new[] { '-' });

            // Loop para percorrer todas as cifras
            for (int i = 0; i < arrayTextoCifradoSeparado.Length; i++)
            {
                // Pega o número armazenado na string auxiliar
                numCifradoAux = BigInteger.Parse(arrayTextoCifradoSeparado[i]);

                // Realiza a conta: (intAux ^ key_Descrypt) % moduloN
                numOriginal = BigInteger.ModPow(numCifradoAux, key_Descrypt, moduloN);

                // Converte de número para caractere pela tabela ASCII
                textoOriginal += Convert.ToChar((int)numOriginal);
            }

            // Retorna o texto original
            return textoOriginal;
        }
    }
}
